#!/usr/bin/env python3
"""
mikrotik_subnet_updater.py - Push a country's IPv4 prefixes into a MikroTik router

What it does
    Asks for a country code (e.g. IR) and a MikroTik router IP, then makes the
    firewall address-list named after the country (list=IR) on the router match
    the country's prefix list, i.e. it runs the equivalent of:

        /ip firewall address-list add list=IR address=<prefix>

    Only the difference is applied: missing prefixes are added and prefixes
    that are no longer in the country list are removed, so the list is never
    emptied while it is being updated. Other lists are not touched.
    Nothing is changed on the router until you confirm.

Usage
    ./country2subnet.py IR                 # first, build the prefix list
    ./mikrotik_subnet_updater.py
    Enter country code (e.g. IR): ir
    Enter MikroTik router IP: 192.168.88.1
    Username [admin]:
    Password:

Input
    ./iplookup-results/<cc>_ipv4_prefixes.txt, written by country2subnet.py
    (run it from the same directory).

Router requirements
    RouterOS 7.1 or newer with the REST API enabled (the www-ssl or www
    service under /ip service) and a user with write access to the firewall.
    HTTPS is tried first (self-signed certificates are accepted), then HTTP.

Requirements
    Python 3 and the 'requests' module. Needs network access to the router.
"""

import os
import sys
import getpass
import ipaddress
import requests
import urllib3

# Routers normally use a self-signed certificate.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RESULTS_DIR = os.path.abspath("iplookup-results")
ENDPOINT = "/rest/ip/firewall/address-list"


def load_prefixes(country):
    """Read the prefix list written by country2subnet.py."""
    path = os.path.join(RESULTS_DIR, f"{country}_ipv4_prefixes.txt")

    if not os.path.isfile(path):
        print(f"ERROR: {path} not found.")
        print(f"Run './country2subnet.py {country.upper()}' from this directory first.")
        sys.exit(1)

    prefixes = []

    with open(path) as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            try:
                prefixes.append(str(ipaddress.IPv4Network(line)))
            except ValueError:
                print(f"Skipping invalid line: {line}")

    return prefixes


def connect(router, user, password):
    """Return (session, base_url) for the first scheme that answers."""
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
            print("ERROR: Login failed (wrong username or password).")
            sys.exit(1)

        if response.ok:
            print(f"Connected to '{response.json().get('name', '?')}' over {scheme.upper()}.")
            return session, base

    print(f"ERROR: Could not reach the REST API on {router}.")
    print("Check the IP, that www-ssl (or www) is enabled in /ip service, and RouterOS is 7.1+.")
    sys.exit(1)


def main():

    country = input("Enter country code (e.g. IR): ").strip().lower()

    if len(country) != 2 or not country.isalpha():
        print("Invalid country code (use 2 letters, e.g. IR).")
        sys.exit(1)

    wanted = load_prefixes(country)

    # The router list name is the upper-case country code (list=IR);
    # RouterOS list names are case-sensitive.
    list_name = country.upper()

    if not wanted:
        print("The prefix list is empty, nothing to do.")
        sys.exit(1)

    print(f"Loaded {len(wanted)} prefixes for '{list_name}'.")

    router = input("Enter MikroTik router IP: ").strip()

    try:
        ipaddress.ip_address(router)
    except ValueError:
        print("Invalid router IP address.")
        sys.exit(1)

    user = input("Username [admin]: ").strip() or "admin"
    password = getpass.getpass("Password: ")

    session, base = connect(router, user, password)

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

    print(f"\nList '{list_name}' on {router}: {len(existing)} entries now")
    print(f"  to add    : {len(to_add)}")
    print(f"  to remove : {len(to_remove)}")
    print(f"  unchanged : {len(existing) - len(to_remove)}")

    if not to_add and not to_remove:
        print("Already up to date.")
        return

    for p in to_add[:3]:
        print(f"  /ip firewall address-list add list={list_name} address={p}")

    if len(to_add) > 3:
        print("  ...")

    if input("\nApply these changes? [y/N]: ").strip().lower() != "y":
        print("Cancelled, nothing changed.")
        return

    failed = 0

    for i, p in enumerate(to_add, 1):
        r = session.put(
            base + ENDPOINT,
            json={"list": list_name, "address": p},
            timeout=30,
        )

        if not r.ok:
            failed += 1
            print(f"  FAILED to add {p}: {r.status_code} {r.text.strip()}")

        if i % 100 == 0:
            print(f"  added {i}/{len(to_add)}")

    for entry_id in to_remove:
        r = session.delete(f"{base}{ENDPOINT}/{entry_id}", timeout=30)

        if not r.ok:
            failed += 1
            print(f"  FAILED to remove {entry_id}: {r.status_code} {r.text.strip()}")

    print(f"\nDone: {len(to_add)} added, {len(to_remove)} removed, {failed} failed.")


if __name__ == "__main__":
    main()
