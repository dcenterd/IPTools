#!/usr/bin/python3
"""
asn2prefix.py - owner info, routing summary and announced prefixes of an AS

Usage
    ./asn2prefix.py                  # asks for the AS number
    ./asn2prefix.py AS15169          # no questions asked (15169 works too)
    ./asn2prefix.py AS15169 --json   # one JSON document on stdout, for scripts

Output
    Printed on screen. With --json a single JSON document is printed instead
    (progress and warnings go to stderr, errors become {"error": ...} and the
    exit code is 1).

Data source
    RIPEstat public API (https://stat.ripe.net/data): as-overview, whois,
    asn-neighbours and announced-prefixes.

Requirements
    Python 3 and the 'requests' module. Needs internet access.
"""
import argparse
import ipaddress
import json
import sys

import requests

BASE_URL = "https://stat.ripe.net/data"


def ripe_query(endpoint, resource):
    """Query a RIPEstat endpoint; return its data dict ({} on failure)."""
    try:
        response = requests.get(
            f"{BASE_URL}/{endpoint}/data.json",
            params={"resource": resource},
            timeout=20,
        )
        response.raise_for_status()
        return response.json().get("data", {})
    except requests.RequestException as e:
        print(f"WARNING: {endpoint} query failed: {e}", file=sys.stderr)
        return {}


def whois_fields(asn):
    """Collect aut-num / organisation / role fields from the whois record."""
    fields = {}
    for group in ripe_query("whois", asn).get("records", []):
        for r in group:
            fields.setdefault(r["key"], [])
            if r["value"] not in fields[r["key"]]:
                fields[r["key"]].append(r["value"])
    return fields


def normalise_asn(text):
    asn = text.strip().upper()
    return asn if asn.startswith("AS") else "AS" + asn


def lookup(asn):
    """Collect everything about an AS into one dict (printed or dumped as JSON by the caller)."""
    overview = ripe_query("as-overview", asn)
    whois = whois_fields(asn)
    neighbours = ripe_query("asn-neighbours", asn).get("neighbour_counts", {})
    announced = ripe_query("announced-prefixes", asn)

    v4, v6 = [], []
    for item in announced.get("prefixes", []):
        p = item.get("prefix")
        if not p:
            continue
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        (v4 if net.version == 4 else v6).append(net)

    v4.sort(key=lambda n: (int(n.network_address), n.prefixlen))
    v6.sort(key=lambda n: (int(n.network_address), n.prefixlen))

    # Count addresses once, even where announced prefixes overlap.
    v4_addresses = sum(n.num_addresses for n in ipaddress.collapse_addresses(v4))

    block = overview.get("block") or {}
    return {
        "asn": asn,
        "found": bool(overview or whois or v4 or v6),
        "holder": overview.get("holder"),
        "announcing": bool(overview.get("announced")),
        "as_name": whois.get("as-name", []),
        "description": whois.get("descr", []),
        "organisation": whois.get("org-name", whois.get("org", [])),
        "country": whois.get("country", []),
        "registry": block.get("name"),
        "block": {"resource": block.get("resource"), "description": block.get("desc")} if block.get("resource") else None,
        "abuse": whois.get("abuse-mailbox", []),
        "contacts": whois.get("admin-c", []) + whois.get("tech-c", []),
        "created": whois.get("created", []),
        "last_modified": whois.get("last-modified", []),
        "source": whois.get("source", []),
        "routing": {
            "ipv4_prefixes": len(v4),
            "ipv4_addresses": v4_addresses,
            "ipv6_prefixes": len(v6),
            "neighbours": {
                "unique": neighbours.get("unique"),
                "upstream_side": neighbours.get("left"),
                "downstream_side": neighbours.get("right"),
            } if neighbours else None,
        },
        "prefixes": {"ipv4": [str(n) for n in v4], "ipv6": [str(n) for n in v6]},
    }


def show(label, value):
    if value:
        print(f"{label:<12}: {value}")


def header(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def render(d):
    """Print the dict returned by lookup() as the familiar text report."""
    header(f"AS OWNER INFORMATION ({d['asn']})")
    show("Holder", d["holder"])
    show("Announcing", "Yes" if d["announcing"] else "No (not announced now)")
    show("AS name", ", ".join(d["as_name"]))
    show("Description", "; ".join(d["description"]))
    show("Organisation", ", ".join(d["organisation"]))
    show("Country", ", ".join(d["country"]))
    show("Registry", d["registry"])
    show("Block", f"{d['block']['resource']} ({d['block']['description']})" if d["block"] else "")
    show("Abuse", ", ".join(d["abuse"]))
    show("Contacts", ", ".join(d["contacts"]))
    show("Created", ", ".join(d["created"]))
    show("Last mod.", ", ".join(d["last_modified"]))
    show("Source", ", ".join(d["source"]))

    r = d["routing"]
    header("ROUTING SUMMARY")
    print(f"IPv4 prefixes : {r['ipv4_prefixes']}")
    print(f"IPv4 addresses: {r['ipv4_addresses']:,}")
    print(f"IPv6 prefixes : {r['ipv6_prefixes']}")
    n = r["neighbours"]
    if n:
        def val(x):
            return "n/a" if x is None else x
        print(
            f"Neighbours    : {val(n['unique'])} "
            f"(upstream-side {val(n['upstream_side'])}, "
            f"downstream-side {val(n['downstream_side'])})"
        )

    prefixes = d["prefixes"]["ipv4"] + d["prefixes"]["ipv6"]
    header(f"ANNOUNCED PREFIXES ({len(prefixes)})")
    for p in prefixes:
        print(p)


def main():
    ap = argparse.ArgumentParser(description="Owner info, routing summary and announced prefixes of an AS (RIPEstat).")
    ap.add_argument("asn", nargs="?", help="AS number, e.g. AS15169 or 15169 (asked for if omitted)")
    ap.add_argument("--json", action="store_true", help="print one JSON document instead of the text report (never prompts)")
    args = ap.parse_args()

    if args.asn:
        text = args.asn
    elif args.json:
        print(json.dumps({"error": "an AS number is required with --json"}))
        return 1
    else:
        text = input("Enter AS number (e.g. AS58224): ")
    asn = normalise_asn(text)
    if not asn[2:].isdigit():
        msg = f"'{text.strip()}' is not a valid AS number (expected e.g. AS15169)"
        print(json.dumps({"error": msg}) if args.json else f"ERROR: {msg}")
        return 1

    data = lookup(asn)
    if not data["found"]:
        msg = f"no data found for {asn} (unknown AS, or RIPEstat unreachable)"
        print(json.dumps({"error": msg}) if args.json else f"ERROR: {msg}")
        return 1

    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        render(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
