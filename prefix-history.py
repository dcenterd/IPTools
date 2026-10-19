#!/usr/bin/env python3
"""
prefix-history.py - routing history of a prefix or an ASN (RIPEstat routing-history).

Usage:
    prefix-history.py <prefix|ASN> [--all] [--related]
    prefix-history.py 193.0.0.0/21        # which ASNs originated it, and when
    prefix-history.py AS3333              # every prefix the ASN has originated

For each origin / prefix it shows the first and last time it was seen in BGP,
whether it is announced right now, and the separate announcement periods
(gaps of more than a few days between sightings start a new period).
For a prefix, only that exact prefix is shown unless --related is given.
Only the most recent periods / prefixes are listed unless --all is given.

Data source: RIPEstat routing-history and as-overview (public RIS data).
"""
import argparse
import sys
from datetime import datetime, timedelta

import requests

RIPE_HISTORY_API = "https://stat.ripe.net/data/routing-history/data.json"
RIPE_AS_API = "https://stat.ripe.net/data/as-overview/data.json"

MERGE_GAP = timedelta(days=2)  # sightings closer than this are one period
SHOWN_PERIODS = 10
SHOWN_PREFIXES = 40


def parse_time(value):
    return datetime.fromisoformat(value)


def get_history(resource):
    r = requests.get(RIPE_HISTORY_API, params={"resource": resource}, timeout=30)
    r.raise_for_status()
    return r.json()["data"]


def get_as_name(asn):
    try:
        r = requests.get(RIPE_AS_API, params={"resource": f"AS{asn}"}, timeout=10)
        r.raise_for_status()
        return r.json().get("data", {}).get("holder") or ""
    except requests.RequestException:
        return ""


def merge_periods(timelines):
    """Collapse the 12-day timeline buckets into continuous announcement periods."""
    periods = []
    for t in sorted(timelines, key=lambda t: t["starttime"]):
        start, end = parse_time(t["starttime"]), parse_time(t["endtime"])
        peers = t.get("full_peers_seeing") or 0
        if periods and start - periods[-1]["end"] <= MERGE_GAP:
            periods[-1]["end"] = max(periods[-1]["end"], end)
            periods[-1]["peers"] = peers
        else:
            periods.append({"start": start, "end": end, "peers": peers})
    return periods


def is_active(periods, data):
    if not periods:
        return False
    cutoff = parse_time(data["query_endtime"]) - timedelta(seconds=data["time_granularity"])
    return periods[-1]["end"] >= cutoff


def fmt_date(dt):
    return dt.strftime("%Y-%m-%d")


def fmt_span(period):
    days = (period["end"] - period["start"]).days + 1
    return f"{fmt_date(period['start'])} -> {fmt_date(period['end'])}  ({days} d)"


def collect(data):
    """Return [(origin, prefix, periods)] sorted by most recently seen first."""
    rows = []
    for origin_entry in data["by_origin"]:
        for p in origin_entry["prefixes"]:
            periods = merge_periods(p["timelines"])
            if periods:
                rows.append((origin_entry["origin"], p["prefix"], periods))
    rows.sort(key=lambda r: r[2][-1]["end"], reverse=True)
    return rows


def show_prefix(data, rows, show_all):
    peers_total = data.get("latest_max_ff_peers", {})
    by_origin = {}
    for origin, prefix, periods in rows:
        by_origin.setdefault(origin, []).append((prefix, periods))

    for origin, entries in by_origin.items():
        name = get_as_name(origin)
        for prefix, periods in entries:
            active = is_active(periods, data)
            total_days = sum((p["end"] - p["start"]).days + 1 for p in periods)
            print(f"AS{origin}  {name}")
            print(f"  prefix       : {prefix}")
            print(f"  first seen   : {fmt_date(periods[0]['start'])}")
            print(f"  last seen    : {fmt_date(periods[-1]['end'])}")
            status = "ANNOUNCED NOW" if active else "not announced"
            if active:
                family = "v6" if ":" in prefix else "v4"
                total = peers_total.get(family)
                seen = periods[-1]["peers"]
                status += f" (seen by ~{seen:.0f}" + (f" of {total}" if total else "") + " full-feed peers)"
            print(f"  status       : {status}")
            print(f"  active days  : {total_days} in {len(periods)} period(s)")
            shown = periods if show_all else periods[-SHOWN_PERIODS:]
            hidden = len(periods) - len(shown)
            print("  periods      :")
            if hidden:
                print(f"    ... {hidden} older period(s) hidden, use --all")
            for p in shown:
                print(f"    {fmt_span(p)}")
            print()

    if len(by_origin) > 1:
        print(f"Origin changes: {len(by_origin)} different ASNs have originated this prefix.")


def show_asn(data, rows, show_all):
    active_rows = [r for r in rows if is_active(r[2], data)]
    print(f"Prefixes ever originated : {len(rows)}")
    print(f"Announced right now      : {len(active_rows)}")
    print(f"Withdrawn                : {len(rows) - len(active_rows)}\n")

    shown = rows if show_all else rows[:SHOWN_PREFIXES]
    print(f"{'PREFIX':<44}{'FIRST SEEN':<12}{'LAST SEEN':<12}{'PERIODS':<9}STATUS")
    for _, prefix, periods in shown:
        status = "active" if is_active(periods, data) else "withdrawn"
        print(f"{prefix:<44}{fmt_date(periods[0]['start']):<12}"
              f"{fmt_date(periods[-1]['end']):<12}{len(periods):<9}{status}")
    if len(rows) > len(shown):
        print(f"... {len(rows) - len(shown)} more prefix(es) hidden, use --all")


def main():
    ap = argparse.ArgumentParser(description="Routing history of a prefix or ASN (RIPEstat)")
    ap.add_argument("resource", help="prefix (193.0.0.0/21, 2001:db8::/32) or ASN (AS3333 / 3333)")
    ap.add_argument("--all", action="store_true", help="show every period / prefix")
    ap.add_argument("--related", action="store_true",
                    help="for a prefix, also show overlapping less/more-specific prefixes")
    args = ap.parse_args()

    resource = args.resource.strip()
    is_asn = resource.upper().startswith("AS") or resource.isdigit()
    if is_asn:
        resource = "AS" + resource.upper().removeprefix("AS")

    print(f"\nRouting history for {resource}\n")
    try:
        data = get_history(resource)
    except (requests.RequestException, KeyError, ValueError) as e:
        print(f"Error: could not fetch routing history ({e})")
        sys.exit(1)

    rows = collect(data)
    if not rows:
        print("No routing history found - this resource has never been seen in BGP.")
        sys.exit(0)

    if not is_asn and not args.related:
        exact = [r for r in rows if r[1] == resource]
        if len(exact) < len(rows):
            print(f"({len(rows) - len(exact)} overlapping less/more-specific prefix record(s) "
                  f"hidden, use --related)\n")
        rows = exact
        if not rows:
            print("This exact prefix has never been seen in BGP (try --related).")
            sys.exit(0)

    print(f"History window: {data['query_starttime'][:10]} -> {data['query_endtime'][:10]}\n")
    if is_asn:
        show_asn(data, rows, args.all)
    else:
        show_prefix(data, rows, args.all)


if __name__ == "__main__":
    main()
