#!/usr/bin/env python3
"""
prefix-history.py - routing history of a prefix or an ASN (RIPEstat routing-history).

Usage:
    prefix-history.py <prefix|ASN> [--all] [--related] [--json]
    prefix-history.py 193.0.0.0/21        # which ASNs originated it, and when
    prefix-history.py AS3333              # every prefix the ASN has originated
    prefix-history.py AS3333 --json       # one JSON document on stdout, for scripts

For each origin / prefix it shows the first and last time it was seen in BGP,
whether it is announced right now, and the separate announcement periods
(gaps of more than a few days between sightings start a new period).
For a prefix, only that exact prefix is shown unless --related is given.
Only the most recent periods / prefixes are listed unless --all is given.

With --json a single JSON document is printed instead. It always contains every
period and prefix (--all only affects the text report). Progress and warnings go
to stderr, errors become {"error": ...} with exit code 1.

Data source: RIPEstat routing-history and as-overview (public RIS data).
"""
import argparse
import json
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
    """Routing history of a resource (one retry: the API occasionally times out)."""
    for attempt in (1, 2):
        try:
            r = requests.get(RIPE_HISTORY_API, params={"resource": resource}, timeout=30)
            r.raise_for_status()
            return r.json()["data"]
        except (requests.RequestException, ValueError):
            if attempt == 2:
                raise


def get_as_name(asn):
    try:
        r = requests.get(RIPE_AS_API, params={"resource": f"AS{asn}"}, timeout=10)
        r.raise_for_status()
        return r.json().get("data", {}).get("holder") or ""
    except (requests.RequestException, ValueError):
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


def period_dict(period):
    return {"start": fmt_date(period["start"]), "end": fmt_date(period["end"]),
            "days": (period["end"] - period["start"]).days + 1}


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


def build_prefix(data, rows):
    """Prefix view: [{asn, name, prefixes: [...]}] grouped by origin ASN."""
    peers_total = data.get("latest_max_ff_peers", {})
    by_origin = {}
    for origin, prefix, periods in rows:
        by_origin.setdefault(origin, []).append((prefix, periods))

    origins = []
    for origin, entries in by_origin.items():
        items = []
        for prefix, periods in entries:
            active = is_active(periods, data)
            family = "v6" if ":" in prefix else "v4"
            items.append({
                "prefix": prefix,
                "first_seen": fmt_date(periods[0]["start"]),
                "last_seen": fmt_date(periods[-1]["end"]),
                "announced_now": active,
                "peers_seen": round(periods[-1]["peers"]) if active else None,
                "peers_total": peers_total.get(family) if active else None,
                "active_days": sum((p["end"] - p["start"]).days + 1 for p in periods),
                "periods": [period_dict(p) for p in periods],
            })
        origins.append({"asn": f"AS{origin}", "name": get_as_name(origin), "prefixes": items})
    return origins


def build_asn(data, rows):
    """ASN view: summary counts plus one entry per prefix the ASN has originated."""
    prefixes = [{
        "prefix": prefix,
        "first_seen": fmt_date(periods[0]["start"]),
        "last_seen": fmt_date(periods[-1]["end"]),
        "announced_now": is_active(periods, data),
        "periods": [period_dict(p) for p in periods],
    } for _, prefix, periods in rows]
    now = sum(1 for p in prefixes if p["announced_now"])
    return {"ever_originated": len(prefixes), "announced_now": now, "withdrawn": len(prefixes) - now, "prefixes": prefixes}


def render_prefix(origins, show_all):
    for o in origins:
        for p in o["prefixes"]:
            print(f"{o['asn']}  {o['name']}")
            print(f"  prefix       : {p['prefix']}")
            print(f"  first seen   : {p['first_seen']}")
            print(f"  last seen    : {p['last_seen']}")
            status = "ANNOUNCED NOW" if p["announced_now"] else "not announced"
            if p["announced_now"]:
                status += f" (seen by ~{p['peers_seen']}" + (f" of {p['peers_total']}" if p["peers_total"] else "") + " full-feed peers)"
            print(f"  status       : {status}")
            print(f"  active days  : {p['active_days']} in {len(p['periods'])} period(s)")
            shown = p["periods"] if show_all else p["periods"][-SHOWN_PERIODS:]
            hidden = len(p["periods"]) - len(shown)
            print("  periods      :")
            if hidden:
                print(f"    ... {hidden} older period(s) hidden, use --all")
            for per in shown:
                print(f"    {per['start']} -> {per['end']}  ({per['days']} d)")
            print()

    if len(origins) > 1:
        print(f"Origin changes: {len(origins)} different ASNs have originated this prefix.")


def render_asn(a, show_all):
    print(f"Prefixes ever originated : {a['ever_originated']}")
    print(f"Announced right now      : {a['announced_now']}")
    print(f"Withdrawn                : {a['withdrawn']}\n")

    shown = a["prefixes"] if show_all else a["prefixes"][:SHOWN_PREFIXES]
    print(f"{'PREFIX':<44}{'FIRST SEEN':<12}{'LAST SEEN':<12}{'PERIODS':<9}STATUS")
    for p in shown:
        status = "active" if p["announced_now"] else "withdrawn"
        print(f"{p['prefix']:<44}{p['first_seen']:<12}{p['last_seen']:<12}{len(p['periods']):<9}{status}")
    if len(a["prefixes"]) > len(shown):
        print(f"... {len(a['prefixes']) - len(shown)} more prefix(es) hidden, use --all")


def main():
    ap = argparse.ArgumentParser(description="Routing history of a prefix or ASN (RIPEstat)")
    ap.add_argument("resource", help="prefix (193.0.0.0/21, 2001:db8::/32) or ASN (AS3333 / 3333)")
    ap.add_argument("--all", action="store_true", help="show every period / prefix (text report)")
    ap.add_argument("--related", action="store_true",
                    help="for a prefix, also show overlapping less/more-specific prefixes")
    ap.add_argument("--json", action="store_true", help="print one JSON document instead of the text report")
    args = ap.parse_args()

    def done(msg, code):
        """Final message: plain text, or a JSON document in --json mode."""
        if args.json:
            print(json.dumps({"error": msg} if code else {"resource": resource, "found": False, "message": msg}))
        else:
            print(f"Error: {msg}" if code else msg)
        return code

    resource = args.resource.strip()
    is_asn = resource.upper().startswith("AS") or resource.isdigit()
    if is_asn:
        resource = "AS" + resource.upper().removeprefix("AS")

    if not args.json:
        print(f"\nRouting history for {resource}\n")
    try:
        data = get_history(resource)
    except (requests.RequestException, KeyError, ValueError) as e:
        return done(f"could not fetch routing history ({e})", 1)

    rows = collect(data)
    if not rows:
        return done("No routing history found - this resource has never been seen in BGP.", 0)

    hidden_related = 0
    if not is_asn and not args.related:
        exact = [r for r in rows if r[1] == resource]
        hidden_related = len(rows) - len(exact)
        if hidden_related and not args.json:
            print(f"({hidden_related} overlapping less/more-specific prefix record(s) "
                  f"hidden, use --related)\n")
        rows = exact
        if not rows:
            return done("This exact prefix has never been seen in BGP (try --related).", 0)

    window = {"start": data["query_starttime"][:10], "end": data["query_endtime"][:10]}
    if is_asn:
        view = build_asn(data, rows)
    else:
        view = build_prefix(data, rows)

    if args.json:
        doc = {"resource": resource, "type": "asn" if is_asn else "prefix", "found": True, "window": window}
        if is_asn:
            doc.update(view)
        else:
            doc.update(origins=view, origin_changes=len(view) > 1, hidden_related=hidden_related)
        print(json.dumps(doc, indent=2, ensure_ascii=False))
        return 0

    print(f"History window: {window['start']} -> {window['end']}\n")
    if is_asn:
        render_asn(view, args.all)
    else:
        render_prefix(view, args.all)
    return 0


if __name__ == "__main__":
    sys.exit(main())
