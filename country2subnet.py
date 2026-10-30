#!/usr/bin/env python3
"""
country2subnet.py - Build IPv4 prefix lists per country

Author:  Zareh Kasparian
Updated: 2026-09-24

What it does
    Builds the list of IPv4 prefixes registered to one or more countries,
    from the delegated statistics published by all five RIRs (RIPE NCC,
    APNIC, ARIN, LACNIC, AFRINIC). Any country in the world works.

Usage
    country2subnet.py                 # asks which country to look for
    country2subnet.py IR              # Iran
    country2subnet.py IR AM TR        # several countries
    country2subnet.py IR,AM,TR        # commas work too
    country2subnet.py --refresh DE    # ignore the cached downloads
    country2subnet.py IR --json       # one JSON document on stdout, for scripts
    country2subnet.py IR --output-dir /srv/lists   # write the files elsewhere
    country2subnet.py IR --json --no-save          # do not write any files

    Countries are 2-letter ISO 3166-1 codes (IR, DE, US, GB, ...).
    Use GB for the United Kingdom, not UK.

Output (in ./iplookup-results/, one pair of files per country)
    <cc>_ipv4_prefixes.txt    one prefix per line
    <cc>_ipv4_mikrotik.rsc    MikroTik commands, address-list name = <cc>
                              (e.g. /ip firewall address-list add list=ir ...)

Data source
    https://ftp.ripe.net/pub/stats/<registry>/delegated-<registry>-extended-latest
    Downloads (about 45 MB in total) are cached in ./iplookup-results/.cache
    for 12 hours.

JSON mode
    --json prints a single JSON document ({"countries": {"IR": {"found", "count",
    "addresses", "prefixes", "files"}}}) and never prompts. Download progress and
    warnings go to stderr; errors become {"error": ...} with exit code 1. The
    prefix files are still written (unless --no-save) and listed under "files".

Note
    These lists show where address space is registered, which is not always
    where the addresses are used or geolocated.

Requirements
    Python 3 and the 'requests' module. Needs internet access.
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime

import requests


BASE_URL = "https://ftp.ripe.net/pub/stats"

# RIPE mirrors the delegated files of every registry, so any country works.
SOURCES = {
    "RIPE NCC": f"{BASE_URL}/ripencc/delegated-ripencc-extended-latest",
    "APNIC":    f"{BASE_URL}/apnic/delegated-apnic-extended-latest",
    "ARIN":     f"{BASE_URL}/arin/delegated-arin-extended-latest",
    "LACNIC":   f"{BASE_URL}/lacnic/delegated-lacnic-extended-latest",
    "AFRINIC":  f"{BASE_URL}/afrinic/delegated-afrinic-extended-latest",
}

OUTPUT_DIR = os.path.abspath("iplookup-results")  # in the current directory
CACHE_DIR = os.path.join(OUTPUT_DIR, ".cache")
CACHE_MAX_AGE = 12 * 3600  # seconds
JSON_MODE = False          # set by --json: progress goes to stderr so stdout stays a single JSON document


def progress(msg=""):
    print(msg, file=sys.stderr if JSON_MODE else sys.stdout)


def parse_countries(values):
    """Turn ['ir', 'AM,tr'] into ['IR', 'AM', 'TR'] (validated, de-duplicated)."""
    codes = []

    for value in values:
        for code in re.split(r"[,\s]+", value.strip()):
            if not code:
                continue

            code = code.upper()

            if not re.fullmatch(r"[A-Z]{2}", code):
                raise ValueError(
                    f"'{code}' is not a 2-letter country code. "
                    "Examples: IR, DE, US, GB"
                )

            if code not in codes:
                codes.append(code)

    return codes


def ask_countries():
    print("Which country do you want to look for?")
    print("Use the 2-letter ISO code. Several can be separated by commas.")
    print("  Examples:  IR        (Iran)")
    print("             DE        (Germany)")
    print("             IR,AM,TR  (Iran, Armenia and Turkey)")
    print()

    while True:
        try:
            answer = input("Enter country code(s): ").strip()
        except EOFError:
            raise ValueError("no country code given")

        if answer:
            return parse_countries([answer])


def fetch(name, url, refresh):
    """Return the path of the (possibly cached) delegated file."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, os.path.basename(url))

    if (
        not refresh
        and os.path.exists(path)
        and time.time() - os.path.getmtime(path) < CACHE_MAX_AGE
    ):
        progress(f"  {name:9} using cached copy")
        return path

    progress(f"  {name:9} downloading...")

    tmp = path + ".part"

    with requests.get(url, timeout=60, stream=True) as response:
        response.raise_for_status()

        with open(tmp, "wb") as f:
            for chunk in response.iter_content(chunk_size=1 << 20):
                f.write(chunk)

    os.replace(tmp, path)

    return path


def get_ipv4(countries, refresh=False):
    """Return {country code: sorted list of IPv4 networks}."""
    wanted = set(countries)
    found = defaultdict(set)

    progress("Loading RIR delegated statistics...")

    for name, url in SOURCES.items():
        path = fetch(name, url, refresh)

        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:

                # Skip comments and anything that is not IPv4
                if line.startswith("#") or "|ipv4|" not in line:
                    continue

                fields = line.rstrip("\n").split("|")

                # registry|cc|type|start|value|date|status[|extensions]
                if len(fields) < 7:
                    continue

                country = fields[1]

                if country not in wanted:
                    continue

                start = fields[3]

                try:
                    count = int(fields[4])

                    # Convert start + number of addresses into CIDR networks;
                    # this also handles allocations that are not a power of 2.
                    first = ipaddress.IPv4Address(start)
                    last = ipaddress.IPv4Address(int(first) + count - 1)

                    found[country].update(
                        ipaddress.summarize_address_range(first, last)
                    )

                except ValueError:
                    continue

    return {
        country: sorted(found[country], key=lambda x: int(x.network_address))
        for country in countries
    }


def save_results(country, networks):

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    tag = country.lower()
    now = datetime.now().isoformat()

    txt_file = os.path.join(OUTPUT_DIR, f"{tag}_ipv4_prefixes.txt")
    rsc_file = os.path.join(OUTPUT_DIR, f"{tag}_ipv4_mikrotik.rsc")

    # Plain text
    with open(txt_file, "w") as f:

        f.write(f"# {country} IPv4 prefixes\n")
        f.write(f"# Total subnets: {len(networks)}\n")
        f.write(f"# Updated: {now}\n\n")

        for network in networks:
            f.write(f"{network}\n")

    # MikroTik format
    with open(rsc_file, "w") as f:

        f.write(f"# {country} IPv4 address list\n")
        f.write(f"# Total subnets: {len(networks)}\n")
        f.write(f"# Updated: {now}\n\n")

        for network in networks:

            f.write(
                f'/ip firewall address-list add '
                f'list={tag} address={network}\n'
            )

    return txt_file, rsc_file


def main():
    global OUTPUT_DIR, CACHE_DIR, JSON_MODE

    parser = argparse.ArgumentParser(
        description="Build IPv4 prefix lists for one or more countries.",
        epilog="Example: country2subnet.py IR AM",
    )
    parser.add_argument(
        "countries",
        nargs="*",
        metavar="CC",
        help="2-letter ISO country code(s), e.g. IR DE US",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="ignore cached downloads and fetch fresh data",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print one JSON document instead of the text report (never prompts)",
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        help="folder for the prefix files and the download cache (default: ./iplookup-results)",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="do not write the .txt / .rsc files",
    )
    args = parser.parse_args()

    JSON_MODE = args.json
    if args.output_dir:
        OUTPUT_DIR = os.path.abspath(args.output_dir)
        CACHE_DIR = os.path.join(OUTPUT_DIR, ".cache")

    def fail(msg):
        print(json.dumps({"error": msg}) if args.json else msg)
        return 1

    if not args.json:
        print("=" * 60)
        print(" Country IPv4 Prefix Updater")
        print("=" * 60)

    try:
        if args.countries:
            countries = parse_countries(args.countries)
        elif args.json:
            return fail("at least one country code is required with --json")
        else:
            countries = ask_countries()

        if not args.json:
            print()
        results = get_ipv4(countries, refresh=args.refresh)
    except ValueError as e:
        return fail(str(e))
    except (requests.RequestException, OSError) as e:
        return fail(f"could not download the RIR statistics ({e})")

    report = {}

    for country, networks in results.items():

        files = None
        if networks and not args.no_save:
            files = save_results(country, networks)

        report[country] = {
            "found": bool(networks),
            "count": len(networks),
            "addresses": sum(n.num_addresses for n in networks),
            "prefixes": [str(n) for n in networks],
            "files": {"txt": files[0], "rsc": files[1]} if files else None,
        }

        if args.json:
            continue

        print()
        print("-" * 60)

        if not networks:
            print(
                f"{country}: no IPv4 prefixes found. "
                "Check the code (e.g. GB for the United Kingdom, not UK)."
            )
            continue

        print(f"{country}: found {len(networks)} IPv4 prefixes.")

        if files:
            print()
            print("Files created:")
            print(f"  {files[0]}")
            print(f"  {files[1]}")

        print()
        print("First 20 prefixes:")

        for network in networks[:20]:
            print(f"  {network}")

    if args.json:
        print(json.dumps({"countries": report}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
