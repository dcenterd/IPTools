#!/usr/bin/env python3
"""
iplookup.py - Find out who is behind an IP address

Author:  Zareh Kasparian
Updated: 2026-10-27

What it does
    Reports, for an IP address (IPv4 or IPv6):
      1. BGP prefix and origin ASN that announces the IP
      2. ASN holder (the organisation that owns the AS)
      3. Reverse DNS (PTR) hostname
      4. Every IPv4 / IPv6 prefix announced by that ASN (on screen only with
         --prefixes; always saved to the file and included in --json)

    If the IP is not announced in BGP (no ASN), it shows the registry (whois)
    record instead: block, net name, country, org and allocation status.

Usage
    ./iplookup.py                    # asks for the IP
    ./iplookup.py 8.8.8.8            # no questions asked
    ./iplookup.py 8.8.8.8 --prefixes # also list all IPv4 prefixes of the ASN
    ./iplookup.py 8.8.8.8 --json     # one JSON document on stdout, for scripts
    ./iplookup.py 8.8.8.8 --no-save  # do not write the AS<number>_prefixes.txt file
    echo 8.8.8.8 | ./iplookup.py     # piped input works too

Output
    Printed on screen (the announced prefix containing the queried IP is
    shown in red when output is a terminal), and saved as AS<number>_prefixes.txt in the current
    directory (for example AS15169_prefixes.txt).

    With --json a single JSON document is printed instead (progress and
    warnings go to stderr, errors become {"error": ...} with exit code 1) and
    no file is written unless --save is given. --json never prompts.

Data source
    RIPEstat public API (https://stat.ripe.net/data): network-info,
    as-overview, announced-prefixes, whois and rir-geo.

Requirements
    Python 3 and the 'requests' module. Needs internet access.
"""

import argparse
import ipaddress
import json
import socket
import sys

import requests


BASE_URL = "https://stat.ripe.net/data"


def ripe_query(endpoint, resource):
    """Query a RIPEstat API endpoint (one retry: the API occasionally times out)."""
    url = f"{BASE_URL}/{endpoint}/data.json"
    error = None

    for _attempt in range(2):
        try:
            response = requests.get(
                url,
                params={"resource": resource},
                timeout=15
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except (requests.RequestException, ValueError) as e:
            error = e

    print(f"ERROR: Could not query RIPEstat: {error}", file=sys.stderr)
    return {}


def reverse_dns(ip):
    """Try to resolve reverse DNS."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def registry_info(ip):
    """What the RIR/whois database says about an IP with no BGP route."""
    whois = ripe_query("whois", ip)

    # Each record group is a list of {key, value}; the first one with an
    # inetnum/inet6num key is the block that covers the IP.
    block = {}
    for group in whois.get("records", []):
        keys = {r["key"]: r["value"] for r in group}
        if "inetnum" in keys or "inet6num" in keys:
            block = keys
            break

    geo = ripe_query("rir-geo", ip).get("located_resources", [])

    return {
        "block": (block.get("inetnum") or block.get("inet6num")) if block else None,
        "net_name": block.get("netname"),
        "country": block.get("country"),
        "org": block.get("org"),
        "status": block.get("status"),
        "rir_geo": {"location": geo[0].get("location"), "resource": geo[0].get("resource")} if geo else None,
    }


def sort_prefixes(prefixes):
    v4, v6 = [], []
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        (v4 if net.version == 4 else v6).append(net)
    v4.sort(key=lambda n: (int(n.network_address), n.prefixlen))
    v6.sort(key=lambda n: (int(n.network_address), n.prefixlen))
    return [str(n) for n in v4], [str(n) for n in v6]


def lookup(ip):
    """Collect everything about an IP into one dict. Raises LookupError if RIPEstat has nothing."""
    network = ripe_query("network-info", ip)
    if not network:
        raise LookupError("Could not find network information.")

    asns = network.get("asns", [])
    data = {
        "ip": ip,
        "bgp_prefix": network.get("prefix") if asns else None,
        "announced": bool(asns),
        "asn": f"AS{asns[0]}" if asns else None,
        "holder": None,
        "announcing": None,
        "reverse_dns": reverse_dns(ip),
        "registry": None,
        "prefixes": {"ipv4": [], "ipv6": []},
    }

    if not asns:
        # Not announced in BGP: there is no ASN or prefix to report, but the
        # registry (RIPE database) still knows who the block belongs to.
        data["registry"] = registry_info(ip)
        return data

    overview = ripe_query("as-overview", data["asn"])
    data["holder"] = overview.get("holder")
    if "announced" in overview:
        data["announcing"] = bool(overview["announced"])

    announced = ripe_query("announced-prefixes", data["asn"])
    v4, v6 = sort_prefixes(item.get("prefix") for item in announced.get("prefixes", []) if item.get("prefix"))
    data["prefixes"] = {"ipv4": v4, "ipv6": v6}
    return data


def render(d, show_prefixes=False):
    """Print the dict returned by lookup() as a short key/value report."""
    rows = [("IP", d["ip"])]

    if d["announced"]:
        rows += [
            ("Prefix", d["bgp_prefix"] or "Unknown"),
            ("ASN", d["asn"]),
            ("Holder", d["holder"] or "Unknown"),
        ]
    else:
        reg = d["registry"]
        rows.append(("Prefix", "not announced in BGP"))
        if reg["block"]:
            rows += [
                ("Block", reg["block"]),
                ("Net name", reg["net_name"] or "Unknown"),
                ("Country", reg["country"] or "Unknown"),
                ("Org", reg["org"] or "Unknown"),
                ("Status", reg["status"] or "Unknown"),
            ]
        else:
            rows.append(("Registry", "no whois record found"))
        if reg["rir_geo"]:
            rows.append(("RIR geo", f"{reg['rir_geo']['location'] or 'Unknown'} ({reg['rir_geo']['resource']})"))

    rows.append(("rDNS", d["reverse_dns"] or "none"))

    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"{k:<{width}} : {v}")

    if not (show_prefixes and d["announced"]):
        return

    # Highlight in red the prefix(es) that contain the queried IP (only when
    # printing to a terminal, so piped output stays free of escape codes).
    v4 = d["prefixes"]["ipv4"]
    print(f"\nIPv4 prefixes ({len(v4)}):")
    ip_obj = ipaddress.ip_address(d["ip"])
    use_color = sys.stdout.isatty()
    for p in v4:
        if use_color and ip_obj in ipaddress.ip_network(p, strict=False):
            print(f"\033[31m{p}  <-- {d['ip']}\033[0m")
        else:
            print(p)


def save(d, filename):
    v4, v6 = d["prefixes"]["ipv4"], d["prefixes"]["ipv6"]
    with open(filename, "w") as f:
        f.write(f"IP Address: {d['ip']}\n")
        f.write(f"BGP Prefix: {d['bgp_prefix']}\n")
        f.write(f"ASN: {d['asn']}\n")
        f.write(f"Holder: {d['holder'] or 'Unknown'}\n")
        f.write(f"Reverse DNS: {d['reverse_dns'] or 'No reverse DNS record'}\n\n")

        f.write("=" * 60 + "\n")
        f.write(f"IPv4 Prefixes ({len(v4)})\n")
        f.write("=" * 60 + "\n")
        for p in v4:
            f.write(p + "\n")

        f.write("\n")
        f.write("=" * 60 + "\n")
        f.write(f"IPv6 Prefixes ({len(v6)})\n")
        f.write("=" * 60 + "\n")
        for p in v6:
            f.write(p + "\n")


def main():
    ap = argparse.ArgumentParser(description="Find out who is behind an IP address (RIPEstat).")
    ap.add_argument("ip", nargs="?", help="IPv4 or IPv6 address (asked for if omitted)")
    ap.add_argument("--prefixes", action="store_true", help="also print every IPv4 prefix announced by the ASN (hidden by default)")
    ap.add_argument("--json",action="store_true", help="print one JSON document instead of the text report (never prompts)")
    ap.add_argument("--no-save", action="store_true", help="do not write AS<number>_prefixes.txt")
    ap.add_argument("--save", action="store_true", help="with --json: also write AS<number>_prefixes.txt")
    args = ap.parse_args()

    def fail(msg):
        print(json.dumps({"error": msg}) if args.json else msg)
        return 1

    if args.ip:
        ip = args.ip.strip()
    elif args.json:
        return fail("an IP address is required with --json")
    else:
        ip = input("Enter IP address: ").strip()

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return fail("Invalid IP address.")

    if not args.json:
        print("Querying RIPEstat...", file=sys.stderr)

    try:
        data = lookup(ip)
    except LookupError as e:
        return fail(str(e))

    do_save = data["announced"] and not args.no_save and (args.save or not args.json)
    filename = f"{data['asn']}_prefixes.txt" if do_save else None
    if filename:
        save(data, filename)

    if args.json:
        print(json.dumps(dict(data, saved_to=filename), indent=2, ensure_ascii=False))
    else:
        render(data, show_prefixes=args.prefixes)
        if filename:
            print(f"\nSaved to {filename}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
