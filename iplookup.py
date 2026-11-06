#!/usr/bin/env python3
"""
iplookup.py - Find out who is behind an IP address

Author:  Zareh Kasparian
Updated: 2026-10-27

What it does
    Reports, for an IP address (IPv4 or IPv6):
      1. The RIR (RIPE NCC, ARIN, APNIC, LACNIC, AFRINIC) that manages the IP
      2. BGP prefix and origin ASN that announces the IP
      3. ASN holder (the organisation that owns the AS)
      4. Country code of the IP and of the announcing ASN (RIR delegation data)
      5. City-level geolocation of the IP (RIPEstat geoloc)
      6. Upstream / downstream counts and the top 5 upstream ASNs
      7. Reverse DNS (PTR) hostname
      8. Every IPv4 / IPv6 prefix announced by that ASN (on screen only with
         --prefixes; saved with --save, always included in --json)

    If the IP is not announced in BGP (no ASN), it shows the registry (whois)
    record instead: block, net name, country, org and allocation status.

Usage
    ./iplookup.py                    # asks for the IP
    ./iplookup.py 8.8.8.8            # no questions asked
    ./iplookup.py 8.8.8.8 --prefixes # also list all IPv4 prefixes of the ASN
    ./iplookup.py 8.8.8.8 --json     # one JSON document on stdout, for scripts
    ./iplookup.py --download-db      # fetch the offline databases (~55 MB) once
    ./iplookup.py --update-db        # re-download them to refresh
    ./iplookup.py 8.8.8.8 --offline  # query the local databases, no network
    ./iplookup.py 8.8.8.8 --save     # also write AS<number>_prefixes.txt (nothing is saved by default)
    echo 8.8.8.8 | ./iplookup.py     # piped input works too

Output
    Printed on screen (the announced prefix containing the queried IP is
    shown in red when output is a terminal). Nothing is written to disk unless
    --save is given, which saves AS<number>_prefixes.txt in the current
    directory (for example AS15169_prefixes.txt).

    With --json a single JSON document is printed instead (progress and
    warnings go to stderr, errors become {"error": ...} with exit code 1).
    --json never prompts.

Offline mode
    --download-db fetches two public databases into ~/.cache/iplookup/ (or
    --db-dir): iptoasn.com ip2asn-combined (IP range -> ASN, AS name, country)
    and the NRO combined delegated stats (IP/ASN -> RIR, country, status).
    --update-db re-downloads them (the old copy is kept if a download fails);
    a warning is printed when they are over 7 days old. --offline then answers
    from those files without any network access. It reports RIR, prefix, ASN,
    holder, country codes and (with --prefixes/--save/--json) all prefixes of
    the ASN. Not available offline: geolocation, neighbours, reverse DNS, and
    registry net name / org. The prefix is the CIDR block of the originating
    ASN range that contains the IP, which can be larger or smaller than the
    announced BGP prefix. IPs with no route show the RIR allocation instead.

Data source
    RIPEstat public API (https://stat.ripe.net/data): network-info,
    as-overview, asn-neighbours, geoloc, announced-prefixes, whois (also gives the RIR) and rir-geo.

Requirements
    Python 3 and the 'requests' module. Needs internet access.
"""

import argparse
import datetime
import gzip
import ipaddress
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

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


RIR_NAMES = {"ripe": "RIPE NCC", "arin": "ARIN", "apnic": "APNIC", "lacnic": "LACNIC", "afrinic": "AFRINIC"}


def rir_name(whois):
    """Name of the RIR that manages the IP, from the whois 'authorities' field."""
    for a in whois.get("authorities", []):
        a = a.lower()
        for key, name in RIR_NAMES.items():
            if a.startswith(key):
                return name
    return None


def registry_info(whois, ip):
    """What the RIR/whois database says about an IP with no BGP route."""

    # Each record group is a list of {key, value}. RIPE-style registries
    # (RIPE, APNIC, AFRINIC, LACNIC) use inetnum/inet6num/netname/country/org/status;
    # ARIN uses NetRange/CIDR/NetName/Organization/NetType, and puts the country
    # in a separate OrgName record, so look for it in any group.
    groups = [{r["key"]: r["value"] for r in group} for group in whois.get("records", [])]
    block = next((k for k in groups if "inetnum" in k or "inet6num" in k or "NetRange" in k), {})
    country = block.get("country") or block.get("Country") or next(
        (k["Country"] for k in groups if k.get("Country")), None)

    geo = ripe_query("rir-geo", ip).get("located_resources", [])

    return {
        "block": (block.get("inetnum") or block.get("inet6num") or block.get("CIDR") or block.get("NetRange")) if block else None,
        "net_name": block.get("netname") or block.get("NetName"),
        "country": country,
        "org": block.get("org") or block.get("Organization"),
        "status": block.get("status") or block.get("NetType"),
        "rir_geo": {"location": geo[0].get("location"), "resource": geo[0].get("resource")} if geo else None,
    }


def rir_country(resource):
    """Country code the RIR delegation files assign to an IP/prefix/ASN, or None."""
    geo = ripe_query("rir-geo", resource).get("located_resources", [])
    return geo[0].get("location") if geo else None


def geolocate(ip):
    """City-level location (RIPEstat geoloc, MaxMind-based) as a dict, or None."""
    for res in ripe_query("geoloc", ip).get("located_resources", []):
        locs = res.get("locations") or []
        if locs:
            loc = max(locs, key=lambda x: x.get("covered_percentage", 0))
            return {
                "country": loc.get("country") or None,
                "city": loc.get("city") or None,
                "latitude": loc.get("latitude"),
                "longitude": loc.get("longitude"),
            }
    return None


def neighbours(asn, top=5):
    """Upstream/downstream counts and the busiest upstreams of an ASN (RIPEstat asn-neighbours)."""
    data = ripe_query("asn-neighbours", asn)
    items = data.get("neighbours", [])
    counts = data.get("neighbour_counts", {})
    # 'left' = upstream (provider side), 'right' = downstream (customer side)
    ups = sorted((n for n in items if n.get("type") == "left"), key=lambda n: -n.get("power", 0))[:top]
    with ThreadPoolExecutor(max_workers=top) as pool:
        holders = list(pool.map(lambda n: ripe_query("as-overview", f"AS{n['asn']}").get("holder"), ups))
    return {
        "upstream_count": counts.get("left"),
        "downstream_count": counts.get("right"),
        "top_upstreams": [{"asn": f"AS{n['asn']}", "holder": h, "power": n.get("power")} for n, h in zip(ups, holders)],
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
        "source": "ripestat",
        "bgp_prefix": network.get("prefix") if asns else None,
        "announced": bool(asns),
        "asn": f"AS{asns[0]}" if asns else None,
        "holder": None,
        "rir": None,
        "ip_country": None,
        "asn_country": None,
        "location": geolocate(ip),
        "neighbours": None,
        "announcing": None,
        "reverse_dns": reverse_dns(ip),
        "registry": None,
        "prefixes": {"ipv4": [], "ipv6": []},
    }

    whois = ripe_query("whois", ip)
    data["rir"] = rir_name(whois)

    if not asns:
        # Not announced in BGP: there is no ASN or prefix to report, but the
        # registry (RIPE database) still knows who the block belongs to.
        data["registry"] = registry_info(whois, ip)
        return data

    data["neighbours"] = neighbours(data["asn"])
    data["ip_country"] = rir_country(ip)
    data["asn_country"] = rir_country(data["asn"])

    overview = ripe_query("as-overview", data["asn"])
    data["holder"] = overview.get("holder")
    if "announced" in overview:
        data["announcing"] = bool(overview["announced"])

    announced = ripe_query("announced-prefixes", data["asn"])
    v4, v6 = sort_prefixes(item.get("prefix") for item in announced.get("prefixes", []) if item.get("prefix"))
    data["prefixes"] = {"ipv4": v4, "ipv6": v6}
    return data


# ---------------------------------------------------------------------------
# Offline mode: local copies of two public databases instead of RIPEstat.
#   ip2asn  - iptoasn.com: IP range -> origin ASN, country, AS name (IPv4+IPv6)
#   nro     - NRO combined delegated stats (all five RIRs): IP/ASN -> RIR, country, status
# ---------------------------------------------------------------------------

DB_FILES = {
    "ip2asn": ("https://iptoasn.com/data/ip2asn-combined.tsv.gz", "ip2asn-combined.tsv.gz"),
    "nro": ("https://ftp.ripe.net/pub/stats/ripencc/nro-stats/latest/nro-delegated-stats", "nro-delegated-stats"),
}
DEFAULT_DB_DIR = os.path.join(os.path.expanduser("~"), ".cache", "iplookup")
STALE_DAYS = 7
NRO_REGISTRIES = {"ripencc": "RIPE NCC", "arin": "ARIN", "apnic": "APNIC", "lacnic": "LACNIC",
                  "afrinic": "AFRINIC", "iana": "IANA", "ietf": "IANA"}


def db_path(db_dir, name):
    return os.path.join(db_dir, DB_FILES[name][1])


def _progress(done, total, started, label):
    """Draw a one-line progress bar on stderr (only when stderr is a terminal)."""
    if not sys.stderr.isatty():
        return
    speed = done / max(time.time() - started, 0.001)
    if total:
        frac = min(done / total, 1.0)
        filled = int(frac * 30)
        bar = "#" * filled + "-" * (30 - filled)
        eta = f"  ETA {int((total - done) / speed)}s" if speed and done < total else ""
        line = f"{label}  [{bar}] {frac * 100:5.1f}%  {done / 1e6:.1f}/{total / 1e6:.1f} MB  {speed / 1e6:.1f} MB/s{eta}"
    else:
        line = f"{label}  {done / 1e6:.1f} MB  {speed / 1e6:.1f} MB/s"   # server sent no size
    sys.stderr.write("\r" + line.ljust(100))
    sys.stderr.flush()


def download_db(db_dir, force=False):
    """Download the offline databases into db_dir. Existing files are kept unless force. True on success."""
    try:
        os.makedirs(db_dir, exist_ok=True)
    except OSError as e:
        print(f"ERROR: cannot create {db_dir}: {e}", file=sys.stderr)
        return False

    ok = True
    for name, (url, filename) in DB_FILES.items():
        path = os.path.join(db_dir, filename)
        if os.path.exists(path) and not force:
            print(f"{filename}: already present (use --update-db to refresh)", file=sys.stderr)
            continue
        print(f"Downloading {url} ...", file=sys.stderr)
        tmp = path + ".part"
        try:
            with requests.get(url, stream=True, timeout=60) as resp:
                resp.raise_for_status()
                total = int(resp.headers.get("Content-Length") or 0)
                done, started = 0, time.time()
                with open(tmp, "wb") as f:
                    for chunk in resp.iter_content(64 * 1024):
                        f.write(chunk)
                        done += len(chunk)
                        _progress(done, total, started, filename)
            if sys.stderr.isatty():
                sys.stderr.write("\r" + " " * 100 + "\r")
            os.replace(tmp, path)   # only replace the old copy once the new one is complete
            print(f"{filename}: {os.path.getsize(path) / 1e6:.1f} MB", file=sys.stderr)
        except (requests.RequestException, OSError) as e:
            if sys.stderr.isatty():
                sys.stderr.write("\n")
            print(f"ERROR: could not download {url}: {e}", file=sys.stderr)
            ok = False
            try:
                os.remove(tmp)
            except OSError:
                pass
    return ok


def _addr_int(text, version):
    return int.from_bytes(socket.inet_pton(socket.AF_INET6 if version == 6 else socket.AF_INET, text), "big")


def _cc(value):
    value = (value or "").strip()
    return None if value.upper() in ("", "ZZ", "NONE", "*") else value.upper()


def _range_prefixes(start, end, version):
    cls = ipaddress.IPv6Address if version == 6 else ipaddress.IPv4Address
    return [str(n) for n in ipaddress.summarize_address_range(cls(start), cls(end))]


def _scan_ip2asn(path, ip_int, version):
    """Row of the ip2asn file that contains the IP: (start, end, asn, country, name) or None."""
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 5 or (":" in p[0]) != (version == 6):
                continue
            try:
                start, end = _addr_int(p[0], version), _addr_int(p[1], version)
            except (OSError, ValueError):
                continue
            if start <= ip_int <= end:
                return start, end, int(p[2]), _cc(p[3]), p[4]
    return None


def _asn_ranges(path, asn):
    """Every (start, end, version) range originated by asn in the ip2asn file."""
    out = []
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 5 or p[2] != str(asn):
                continue
            v = 6 if ":" in p[0] else 4
            try:
                out.append((_addr_int(p[0], v), _addr_int(p[1], v), v))
            except (OSError, ValueError):
                continue
    return out


def _scan_nro(path, ip_int, version, asn):
    """RIR rows for the IP block and (if asn) the ASN: (ip_row, asn_row); each is a dict or None."""
    ip_row = asn_row = None
    want = "ipv6" if version == 6 else "ipv4"
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                continue
            p = line.rstrip("\n").split("|")
            if len(p) < 7 or p[3] == "*":
                continue
            kind = p[2]
            try:
                if kind == want and ip_row is None:
                    start = _addr_int(p[3], version)
                    size = 1 << (128 - int(p[4])) if version == 6 else int(p[4])
                    if start <= ip_int < start + size:
                        ip_row = {"rir": NRO_REGISTRIES.get(p[0].lower(), p[0]), "country": _cc(p[1]),
                                  "status": p[6], "start": start, "end": start + size - 1}
                elif kind == "asn" and asn is not None and asn_row is None:
                    start, size = int(p[3]), int(p[4])
                    if start <= asn < start + size:
                        asn_row = {"rir": NRO_REGISTRIES.get(p[0].lower(), p[0]), "country": _cc(p[1])}
            except (OSError, ValueError):
                continue
            if ip_row and (asn_row or asn is None):
                break
    return ip_row, asn_row


def offline_lookup(ip, db_dir, want_prefixes=False):
    """Same result dict as lookup(), built from the local databases (no network)."""
    paths = {name: db_path(db_dir, name) for name in DB_FILES}
    if not all(os.path.exists(x) for x in paths.values()):
        raise LookupError(f"Offline databases not found in {db_dir}. Download them first with: iplookup.py --download-db")

    oldest = min(os.path.getmtime(x) for x in paths.values())
    age_days = (time.time() - oldest) / 86400
    if age_days > STALE_DAYS:
        print(f"WARNING: offline databases are {int(age_days)} days old; refresh with --update-db", file=sys.stderr)

    ip_obj = ipaddress.ip_address(ip)
    version, ip_int = ip_obj.version, int(ip_obj)
    try:
        row = _scan_ip2asn(paths["ip2asn"], ip_int, version)
        asn = row[2] if row and row[2] else None      # ASN 0 = not routed
        ip_row, asn_row = _scan_nro(paths["nro"], ip_int, version, asn)
    except (OSError, EOFError) as e:
        raise LookupError(f"Could not read offline databases ({e}). Try --update-db.")

    data = {
        "ip": ip,
        "source": "offline",
        "db_date": datetime.date.fromtimestamp(oldest).isoformat(),
        "bgp_prefix": None,
        "announced": asn is not None,
        "asn": f"AS{asn}" if asn else None,
        "holder": row[4] if asn else None,
        "rir": ip_row["rir"] if ip_row else None,
        "ip_country": (ip_row and ip_row["country"]) or (row[3] if row else None),
        "asn_country": (asn_row and asn_row["country"]) or None,
        "location": None,
        "neighbours": None,
        "announcing": None,
        "reverse_dns": None,
        "registry": None,
        "prefixes": {"ipv4": [], "ipv6": []},
    }

    if asn is None:
        block = None
        if ip_row:
            cls = ipaddress.IPv6Address if version == 6 else ipaddress.IPv4Address
            block = f"{cls(ip_row['start'])} - {cls(ip_row['end'])}"
        data["registry"] = {"block": block, "net_name": None, "country": data["ip_country"],
                            "org": None, "status": ip_row["status"] if ip_row else None, "rir_geo": None}
        return data

    # The database holds ranges, not announced prefixes: report the CIDR block
    # inside the originating range that contains the IP.
    data["bgp_prefix"] = next(
        (c for c in _range_prefixes(row[0], row[1], version) if ip_obj in ipaddress.ip_network(c)), None)

    if want_prefixes:
        try:
            ranges = _asn_ranges(paths["ip2asn"], asn)
        except (OSError, EOFError) as e:
            raise LookupError(f"Could not read offline databases ({e}). Try --update-db.")
        cidrs = [c for s, e, v in ranges for c in _range_prefixes(s, e, v)]
        v4, v6 = sort_prefixes(cidrs)
        data["prefixes"] = {"ipv4": v4, "ipv6": v6}
    return data


def render(d, show_prefixes=False):
    """Print the dict returned by lookup() as a short key/value report."""
    offline_mode = d.get("source") == "offline"
    rows = [("IP", d["ip"]), ("RIR", d["rir"] or "Unknown")]

    if d["announced"]:
        rows += [
            ("Prefix", d["bgp_prefix"] or "Unknown"),
            ("ASN", d["asn"]),
            ("Holder", d["holder"] or "Unknown"),
            ("IP country", d["ip_country"] or "Unknown"),
            ("ASN country", d["asn_country"] or "Unknown"),
        ]
    else:
        reg = d["registry"]
        rows.append(("Prefix", "not announced in BGP"))
        if reg["block"]:
            # the offline database has no net name / org, so leave those rows out
            rows += [("Block", reg["block"])]
            if not offline_mode:
                rows += [("Net name", reg["net_name"] or "Unknown")]
            rows += [("Country", reg["country"] or "Unknown")]
            if not offline_mode:
                rows += [("Org", reg["org"] or "Unknown")]
            rows += [("Status", reg["status"] or "Unknown")]
        else:
            rows.append(("Registry", "no whois record found"))
        if reg["rir_geo"]:
            rows.append(("RIR geo", f"{reg['rir_geo']['location'] or 'Unknown'} ({reg['rir_geo']['resource']})"))

    loc = d["location"]
    if offline_mode:
        pass
    elif loc:
        place = ", ".join(x for x in (loc["city"], loc["country"]) if x) or "Unknown"
        rows.append(("Geolocation", f"{place} ({loc['latitude']}, {loc['longitude']})"))
    else:
        rows.append(("Geolocation", "Unknown"))

    if offline_mode:
        rows.append(("Source", f"offline databases from {d['db_date']}"))
    else:
        rows.append(("rDNS", d["reverse_dns"] or "none"))

    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"{k:<{width}} : {v}")

    nb = d["neighbours"]
    if nb:
        print(f"\nNeighbours: {nb['upstream_count']} upstream, {nb['downstream_count']} downstream")
        for n in nb["top_upstreams"]:
            print(f"  {n['asn']:<10} {n['holder'] or 'Unknown'}")

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
        f.write(f"RIR: {d['rir'] or 'Unknown'}\n")
        f.write(f"BGP Prefix: {d['bgp_prefix']}\n")
        f.write(f"ASN: {d['asn']}\n")
        f.write(f"Holder: {d['holder'] or 'Unknown'}\n")
        f.write(f"IP Country: {d['ip_country'] or 'Unknown'}\n")
        f.write(f"ASN Country: {d['asn_country'] or 'Unknown'}\n")
        if d["location"]:
            f.write(f"Geolocation: {d['location']['city'] or '-'}, {d['location']['country']} ({d['location']['latitude']}, {d['location']['longitude']})\n")
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
    ap.add_argument("--save", action="store_true", help="write AS<number>_prefixes.txt in the current directory (nothing is saved by default)")
    ap.add_argument("--offline", action="store_true", help="query the local databases instead of RIPEstat (no network; see --download-db)")
    ap.add_argument("--download-db", action="store_true", help="download the offline databases if missing, then exit (or continue if an IP is given)")
    ap.add_argument("--update-db", action="store_true", help="re-download the offline databases even if present, then exit (or continue if an IP is given)")
    ap.add_argument("--db-dir", default=DEFAULT_DB_DIR, help="where the offline databases live (default: ~/.cache/iplookup)")
    args = ap.parse_args()

    def fail(msg):
        print(json.dumps({"error": msg}) if args.json else msg)
        return 1

    if args.download_db or args.update_db:
        if not download_db(args.db_dir, force=args.update_db):
            return 1
        if not args.ip:
            print(f"Offline databases ready in {args.db_dir}", file=sys.stderr)
            return 0

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

    if not args.json and not args.offline:
        print("Querying RIPEstat...", file=sys.stderr)

    try:
        if args.offline:
            data = offline_lookup(ip, args.db_dir, want_prefixes=args.prefixes or args.save or args.json)
        else:
            data = lookup(ip)
    except LookupError as e:
        return fail(str(e))

    do_save = data["announced"] and args.save
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
