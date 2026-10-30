#!/usr/bin/env python3
"""
whois-contacts.py - who do I contact about this IP / ASN?

Usage:
    whois-contacts.py <ip|prefix|ASN> [--json]
    whois-contacts.py 193.0.0.1
    whois-contacts.py AS3333
    whois-contacts.py AS3333 --json     # one JSON document on stdout, for scripts

Prints the abuse contact, the registration record (network / AS name, org,
country, status) and the admin / tech / abuse contacts with e-mail and phone.
For RIPE-managed resources the contact handles (admin-c, tech-c, abuse-c, org)
are resolved through the RIPE Database; for other registries (ARIN, APNIC,
LACNIC, AFRINIC) the contact fields from their whois record are shown as-is.

With --json a single JSON document is printed instead (progress and warnings
go to stderr, errors become {"error": ...} with exit code 1).

Data source: RIPEstat abuse-contact-finder + whois, RIPE Database REST API.
"""
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor

import requests

RIPE_STAT = "https://stat.ripe.net/data"
RIPE_DB = "https://rest.db.ripe.net/search.json"

# attributes of the main object worth showing (RIPE and common RIR keys)
MAIN_KEYS = {
    "inetnum", "inet6num", "aut-num", "netname", "as-name", "descr", "country",
    "status", "org", "admin-c", "tech-c", "abuse-c", "mnt-by", "created", "last-modified",
}
HANDLE_KEYS = ("org", "admin-c", "tech-c", "abuse-c")
# non-RIPE records: skip free-text noise
SKIP_KEYS = {"comment", "ref", "remarks", "source", "import", "export", "mp-import",
             "mp-export", "default", "mp-default", "geoloc", "language"}


def stat(endpoint, resource):
    """RIPEstat data dict, or None if it could not be fetched (one retry: the API occasionally times out)."""
    for _attempt in range(2):
        try:
            r = requests.get(f"{RIPE_STAT}/{endpoint}/data.json",
                             params={"resource": resource}, timeout=20)
            r.raise_for_status()
            return r.json().get("data") or {}
        except (requests.RequestException, ValueError):
            pass
    return None


def db_lookup(handle):
    """Resolve a RIPE DB handle (nic-hdl / organisation) to {attribute: [values]}."""
    try:
        r = requests.get(
            RIPE_DB,
            params={"query-string": handle, "source": "ripe",
                    "type-filter": ["role", "person", "organisation"],
                    "flags": "no-referenced"},
            headers={"Accept": "application/json"}, timeout=15)
        if r.status_code != 200:
            return None
        obj = r.json()["objects"]["object"][0]
    except (requests.RequestException, KeyError, IndexError, ValueError):
        return None

    attrs = {}
    for a in obj["attributes"]["attribute"]:
        attrs.setdefault(a["name"], []).append(a["value"])
    attrs["_type"] = obj.get("type", "")
    return attrs


def flatten(records):
    return [(x["key"], x["value"]) for rec in records for x in rec]


def contact_entry(role, handle, attrs):
    """One resolved contact as a plain dict (attrs is None when the handle could not be resolved)."""
    if attrs is None:
        return {"role": role, "handle": handle, "name": None, "resolved": False,
                "emails": [], "abuse": [], "phones": [], "address": None}
    name = (attrs.get("role") or attrs.get("person") or attrs.get("org-name") or [handle])[0]
    addr = ", ".join(attrs.get("address", [])) if attrs.get("_type") == "organisation" else ""
    return {"role": role, "handle": handle, "name": name, "resolved": True,
            "emails": attrs.get("e-mail", []), "abuse": attrs.get("abuse-mailbox", []),
            "phones": attrs.get("phone", []), "address": addr or None}


def ripe_details(pairs):
    """(registration pairs, contacts) for a RIPE-managed resource; handles are resolved via the RIPE DB."""
    registration, handles = [], []
    for key, value in pairs:
        if key in MAIN_KEYS and key not in HANDLE_KEYS:
            registration.append((key, value))
        elif key in HANDLE_KEYS and (key, value) not in handles:
            handles.append((key, value))

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda kv: db_lookup(kv[1]), handles))
    contacts = [contact_entry(role, handle, attrs) for (role, handle), attrs in zip(handles, results)]
    return registration, contacts


def other_details(pairs):
    """Registration pairs for a non-RIPE record: shown as-is, minus free-text noise."""
    return [(k, v) for k, v in pairs if k.lower() not in SKIP_KEYS and v], []


def normalise(arg):
    arg = arg.strip()
    if arg.upper().startswith("AS") and arg[2:].isdigit():
        return "AS" + arg[2:]
    if arg.isdigit():
        return "AS" + arg
    return arg


def gather(resource):
    """Everything about who to contact for a resource. Raises LookupError if RIPEstat cannot be reached."""
    abuse = stat("abuse-contact-finder", resource)
    whois = stat("whois", resource)
    if abuse is None and whois is None:
        raise LookupError("RIPEstat is unreachable or rejected the resource.")

    emails = (abuse or {}).get("abuse_contacts") or []
    if not emails and whois and "/" not in resource and not resource.startswith("AS"):
        # a single IP can miss the abuse lookup; retry on the covering prefix
        for key, value in flatten(whois.get("records") or []):
            if key in ("inetnum", "inet6num", "CIDR") and "/" in value:
                emails = (stat("abuse-contact-finder", value.split(",")[0].strip()) or {}).get(
                    "abuse_contacts") or []
                break
    authority = ((whois or {}).get("authorities") or ["unknown"])[0]

    data = {"resource": resource, "abuse_contacts": emails, "registry": authority.upper(),
            "found": False, "registration": [], "contacts": []}
    records = (whois or {}).get("records") or []
    if records:
        pairs = flatten(records)
        registration, contacts = ripe_details(pairs) if authority == "ripe" else other_details(pairs)
        data.update(found=True, registration=[{"key": k, "value": v} for k, v in registration], contacts=contacts)
    return data


def render(d):
    """Print the dict returned by gather() as the familiar text report."""
    print(f"\nContacts for {d['resource']}\n")
    print("Abuse contact : " + (", ".join(d["abuse_contacts"]) if d["abuse_contacts"] else "none registered"))
    print(f"Registry      : {d['registry']}\n")

    if not d["found"]:
        print("No whois record found.")
        return

    print("Registration")
    ripe = d["registry"] == "RIPE"
    for item in d["registration"]:
        print(f"  {item['key']:<{14 if ripe else 16}}{item['value']}")

    if d["contacts"]:
        print("\nContacts")
        for c in d["contacts"]:
            if not c["resolved"]:
                print(f"  {c['role']:<8} {c['handle']}  (could not be resolved)")
                continue
            print(f"  {c['role']:<8} {c['handle']} - {c['name']}")
            for label, values in (("e-mail", c["emails"]), ("abuse", c["abuse"]), ("phone", c["phones"])):
                for v in values:
                    print(f"{'':<11}{label}: {v}")
            if c["address"]:
                print(f"{'':<11}address: {c['address']}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Who to contact about an IP, prefix or ASN (RIPEstat + RIPE Database).")
    ap.add_argument("resource", help="IP address, prefix or AS number (e.g. 193.0.0.1, 193.0.0.0/21, AS3333)")
    ap.add_argument("--json", action="store_true", help="print one JSON document instead of the text report")
    args = ap.parse_args()

    resource = normalise(args.resource)
    try:
        data = gather(resource)
    except LookupError as e:
        print(json.dumps({"error": str(e)}) if args.json else f"\nContacts for {resource}\n\nError: {e}")
        return 1

    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        render(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
