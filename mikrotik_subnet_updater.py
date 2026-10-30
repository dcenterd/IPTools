#!/usr/bin/env python3
"""
mikrotik_subnet_updater.py - Push a country's IPv4 prefixes into a MikroTik router

What it does
    Makes the firewall address-list named after the country (list=IR) on the
    router match the country's prefix list, i.e. it runs the equivalent of:

        /ip firewall address-list add list=IR address=<prefix>

    Only the difference is applied: missing prefixes are added and prefixes
    that are no longer in the country list are removed, so the list is never
    emptied while it is being updated. Other lists are not touched.
    Nothing is changed on the router until you confirm (or pass --yes).

Usage
    Interactive (asks for everything, then for confirmation):
        ./country2subnet.py IR                 # first, build the prefix list
        ./mikrotik_subnet_updater.py

    Non-interactive (for scripts and cron):
        export MIKROTIK_PASSWORD='...'         # or --password-file FILE
        ./mikrotik_subnet_updater.py IR 192.168.88.1 -u admin --dry-run   # preview only
        ./mikrotik_subnet_updater.py IR 192.168.88.1 -u admin --yes       # apply
        ./mikrotik_subnet_updater.py IR 192.168.88.1 -u admin --yes --json

    Anything not given on the command line is asked for. There is deliberately
    no --password option (it would show up in the process list): use the
    MIKROTIK_PASSWORD environment variable, --password-file, or the prompt.
    The user name can also come from MIKROTIK_USER.

    --json prints one JSON document (counts, no prefix lists), never prompts, and
    only applies changes together with --yes; without it the run is a preview.
    Exit codes: 0 done / up to date / preview, 1 error, 2 some changes failed.

Input
    ./iplookup-results/<cc>_ipv4_prefixes.txt, written by country2subnet.py
    (run it from the same directory, or point to it with --results-dir).

Router requirements
    RouterOS 7.1 or newer with the REST API enabled (the www-ssl or www
    service under /ip service) and a user with write access to the firewall.
    HTTPS is tried first (self-signed certificates are accepted), then HTTP.

Requirements
    Python 3 and the 'requests' module. Needs network access to the router.
"""

import argparse
import getpass
import ipaddress
import json
import os
import sys

import requests
import urllib3

# Routers normally use a self-signed certificate.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RESULTS_DIR = os.path.abspath("iplookup-results")
ENDPOINT = "/rest/ip/firewall/address-list"


class UpdaterError(Exception):
    """A problem that ends the run (printed, or reported as {"error": ...} with --json)."""


def load_prefixes(country, results_dir):
    """Read the prefix list written by country2subnet.py."""
    path = os.path.join(results_dir, f"{country}_ipv4_prefixes.txt")

    if not os.path.isfile(path):
        raise UpdaterError(f"{path} not found.\n"
                           f"Run './country2subnet.py {country.upper()}' from this directory first.")

    prefixes = []

    with open(path) as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            try:
                prefixes.append(str(ipaddress.IPv4Network(line)))
            except ValueError:
                print(f"Skipping invalid line: {line}", file=sys.stderr)

    return prefixes


def connect(router, user, password):
    """Return (session, base_url, identity, scheme) for the first scheme that answers."""
    session = requests.Session()
    session.auth = (user, password)
    session.verify = False

    for scheme in ("https", "http"):
        base = f"{scheme}://{router}"

        try:
            response = session.get(base + "/rest/system/identity", timeout=10)
        except requests.RequestException:
            continue

        if response.status_code == 401:
            raise UpdaterError("Login failed (wrong username or password).")

        if response.ok:
            return session, base, response.json().get("name", "?"), scheme

    raise UpdaterError(f"Could not reach the REST API on {router}.\n"
                       "Check the IP, that www-ssl (or www) is enabled in /ip service, and RouterOS is 7.1+.")


def read_password(args):
    """Password from --password-file, MIKROTIK_PASSWORD, or (interactive only) the prompt."""
    if args.password_file:
        try:
            with open(args.password_file) as f:
                return f.readline().rstrip("\r\n")
        except OSError as e:
            raise UpdaterError(f"cannot read the password file: {e}")
    if os.environ.get("MIKROTIK_PASSWORD"):
        return os.environ["MIKROTIK_PASSWORD"]
    if args.json:
        raise UpdaterError("no password: set MIKROTIK_PASSWORD or use --password-file (--json never prompts)")
    return getpass.getpass("Password: ")


def run(args, say):
    """Do the whole update. Returns the result dict; raises UpdaterError on problems."""
    def ask(prompt, what):
        if args.json:
            raise UpdaterError(f"{what} is required with --json")
        return input(prompt)

    country = (args.country or ask("Enter country code (e.g. IR): ", "the country code")).strip().lower()
    if len(country) != 2 or not country.isalpha():
        raise UpdaterError("Invalid country code (use 2 letters, e.g. IR).")

    wanted = load_prefixes(country, args.results_dir)

    # The router list name is the upper-case country code (list=IR);
    # RouterOS list names are case-sensitive.
    list_name = country.upper()

    if not wanted:
        raise UpdaterError("The prefix list is empty, nothing to do.")

    say(f"Loaded {len(wanted)} prefixes for '{list_name}'.")

    router = (args.router or ask("Enter MikroTik router IP: ", "the router IP")).strip()
    try:
        ipaddress.ip_address(router)
    except ValueError:
        raise UpdaterError("Invalid router IP address.")

    user = args.user or os.environ.get("MIKROTIK_USER")
    if not user:
        user = "admin" if args.json else (input("Username [admin]: ").strip() or "admin")
    password = read_password(args)

    session, base, identity, scheme = connect(router, user, password)
    say(f"Connected to '{identity}' over {scheme.upper()}.")

    # Current content of the list on the router
    response = session.get(base + ENDPOINT, params={"list": list_name}, timeout=30)
    response.raise_for_status()

    existing = {}

    for entry in response.json():
        if entry.get("list") == list_name:
            existing[entry["address"]] = entry[".id"]

    wanted_set = set(wanted)
    to_add = [p for p in wanted if p not in existing]
    to_remove = [existing[a] for a in existing if a not in wanted_set]

    result = {"country": list_name, "router": router, "identity": identity, "scheme": scheme,
              "wanted": len(wanted), "existing": len(existing), "to_add": len(to_add), "to_remove": len(to_remove),
              "unchanged": len(existing) - len(to_remove), "up_to_date": not to_add and not to_remove,
              "dry_run": True, "applied": False, "added": 0, "removed": 0, "failed": 0, "errors": []}

    say(f"\nList '{list_name}' on {router}: {len(existing)} entries now")
    say(f"  to add    : {len(to_add)}")
    say(f"  to remove : {len(to_remove)}")
    say(f"  unchanged : {len(existing) - len(to_remove)}")

    if result["up_to_date"]:
        say("Already up to date.")
        return result

    for p in to_add[:3]:
        say(f"  /ip firewall address-list add list={list_name} address={p}")

    if len(to_add) > 3:
        say("  ...")

    if args.dry_run:
        say("\nDry run: nothing changed on the router.")
        return result

    if not args.yes:
        if args.json:
            say("Preview only: pass --yes to apply.")
            return result
        try:
            answer = input("\nApply these changes? [y/N]: ").strip().lower()
        except EOFError:
            answer = ""
        if answer != "y":
            say("Cancelled, nothing changed.")
            return result

    result["dry_run"] = False

    def failed(msg):
        result["failed"] += 1
        if len(result["errors"]) < 20:
            result["errors"].append(msg)
        say(f"  FAILED {msg}")

    for i, p in enumerate(to_add, 1):
        r = session.put(
            base + ENDPOINT,
            json={"list": list_name, "address": p},
            timeout=30,
        )

        if r.ok:
            result["added"] += 1
        else:
            failed(f"to add {p}: {r.status_code} {r.text.strip()}")

        if i % 100 == 0:
            say(f"  added {i}/{len(to_add)}")

    for entry_id in to_remove:
        r = session.delete(f"{base}{ENDPOINT}/{entry_id}", timeout=30)

        if r.ok:
            result["removed"] += 1
        else:
            failed(f"to remove {entry_id}: {r.status_code} {r.text.strip()}")

    result["applied"] = True
    say(f"\nDone: {result['added']} added, {result['removed']} removed, {result['failed']} failed.")
    return result


def main():
    ap = argparse.ArgumentParser(
        description="Sync a country's IPv4 prefix list into a MikroTik firewall address-list (RouterOS 7 REST API).",
        epilog="Password: env MIKROTIK_PASSWORD, --password-file, or the prompt. User: -u or env MIKROTIK_USER.")
    ap.add_argument("country", nargs="?", help="2-letter country code, e.g. IR (asked for if omitted)")
    ap.add_argument("router", nargs="?", help="router IP address (asked for if omitted)")
    ap.add_argument("-u", "--user", help="router user (default: env MIKROTIK_USER, else 'admin')")
    ap.add_argument("--password-file", metavar="FILE", help="read the password from the first line of FILE")
    ap.add_argument("-y", "--yes", action="store_true", help="apply without asking for confirmation")
    ap.add_argument("-n", "--dry-run", action="store_true", help="show what would change, change nothing")
    ap.add_argument("--json", action="store_true",
                    help="print one JSON document, never prompt (changes need --yes, otherwise it is a preview)")
    ap.add_argument("--results-dir", default=RESULTS_DIR, metavar="DIR",
                    help="folder with <cc>_ipv4_prefixes.txt from country2subnet.py (default: ./iplookup-results)")
    args = ap.parse_args()

    if args.yes and args.dry_run:
        ap.error("--yes and --dry-run cannot be used together")

    def say(msg):
        if not args.json:
            print(msg)

    try:
        result = run(args, say)
    except UpdaterError as e:
        print(json.dumps({"error": str(e)}) if args.json else f"ERROR: {e}")
        return 1
    except requests.RequestException as e:
        msg = f"router request failed: {e}"
        print(json.dumps({"error": msg}) if args.json else f"ERROR: {msg}")
        return 1
    except (EOFError, KeyboardInterrupt):
        print(json.dumps({"error": "interrupted"}) if args.json else "\nCancelled, nothing more was changed.")
        return 1

    if args.json:
        print(json.dumps(result, indent=2))
    return 2 if result["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
