#!/usr/bin/env python3
"""
whois-contacts.py - who do I contact about this IP / ASN?

Usage:
    whois-contacts.py <ip|prefix|ASN>
    whois-contacts.py 193.0.0.1
    whois-contacts.py AS3333

Prints the abuse contact, the registration record (network / AS name, org,
country, status) and the admin / tech / abuse contacts with e-mail and phone.
For RIPE-managed resources the contact handles (admin-c, tech-c, abuse-c, org)
are resolved through the RIPE Database; for other registries (ARIN, APNIC,
LACNIC, AFRINIC) the contact fields from their whois record are shown as-is.

Data source: RIPEstat abuse-contact-finder + whois, RIPE Database REST API.
"""
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
    try:
        r = requests.get(f"{RIPE_STAT}/{endpoint}/data.json",
                         params={"resource": resource}, timeout=20)
        r.raise_for_status()
        return r.json().get("data") or {}
    except (requests.RequestException, ValueError):
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


def print_contact(role, handle, attrs):
    if attrs is None:
        print(f"  {role:<8} {handle}  (could not be resolved)")
        return
    name = (attrs.get("role") or attrs.get("person") or attrs.get("org-name") or [handle])[0]
    print(f"  {role:<8} {handle} - {name}")
    for key, label in (("e-mail", "e-mail"), ("abuse-mailbox", "abuse"), ("phone", "phone")):
        for v in attrs.get(key, []):
            print(f"{'':<11}{label}: {v}")
    if attrs.get("_type") == "organisation":
        addr = ", ".join(attrs.get("address", []))
        if addr:
            print(f"{'':<11}address: {addr}")


def show_ripe(pairs):
    handles = []
    for key, value in pairs:
        if key in MAIN_KEYS and key not in HANDLE_KEYS:
            print(f"  {key:<14}{value}")
        elif key in HANDLE_KEYS and (key, value) not in handles:
            handles.append((key, value))

    if not handles:
        return
    print("\nContacts")
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda kv: db_lookup(kv[1]), handles))
    for (role, handle), attrs in zip(handles, results):
        print_contact(role, handle, attrs)


def show_other(pairs):
    for key, value in pairs:
        if key.lower() in SKIP_KEYS or not value:
            continue
        print(f"  {key:<16}{value}")


def normalise(arg):
    arg = arg.strip()
    if arg.upper().startswith("AS") and arg[2:].isdigit():
        return "AS" + arg[2:]
    if arg.isdigit():
        return "AS" + arg
    return arg


def main():
    if len(sys.argv) != 2:
        print("Usage: whois-contacts.py <ip|prefix|ASN>")
        sys.exit(1)

    resource = normalise(sys.argv[1])
    print(f"\nContacts for {resource}\n")

    abuse = stat("abuse-contact-finder", resource)
    whois = stat("whois", resource)
    if abuse is None and whois is None:
        print("Error: RIPEstat is unreachable or rejected the resource.")
        sys.exit(1)

    emails = (abuse or {}).get("abuse_contacts") or []
    if not emails and whois and "/" not in resource and not resource.startswith("AS"):
        # a single IP can miss the abuse lookup; retry on the covering prefix
        for key, value in flatten(whois.get("records") or []):
            if key in ("inetnum", "inet6num", "CIDR") and "/" in value:
                emails = (stat("abuse-contact-finder", value.split(",")[0].strip()) or {}).get(
                    "abuse_contacts") or []
                break
    print("Abuse contact : " + (", ".join(emails) if emails else "none registered"))
    authority = ((whois or {}).get("authorities") or ["unknown"])[0]
    print(f"Registry      : {authority.upper()}\n")

    records = (whois or {}).get("records") or []
    if not records:
        print("No whois record found.")
        return

    print("Registration")
    pairs = flatten(records)
    if authority == "ripe":
        show_ripe(pairs)
    else:
        show_other(pairs)
    print()


if __name__ == "__main__":
    main()
