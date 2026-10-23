#!/usr/bin/env python3
"""List the latest published CVEs from NVD + CIRCL, ranked by real-world risk.

Usage:
  cve_checker.py                                # CVEs from the last 3 days, riskiest first
  cve_checker.py --days 7 --severity high       # HIGH and CRITICAL only
  cve_checker.py --keyword "PHP before" --days 30
  cve_checker.py --kev                          # only CVEs known to be exploited (CISA KEV)
  cve_checker.py --days 1 --json > cves.json

Sources (no API key needed):
  NVD API 2.0   main CVE list and CVSS scores        (set NVD_API_KEY for higher rate limits)
  CIRCL         vulnerability.circl.lu: the newest CVE records, plus scores for CVEs NVD has
                not scored yet (taken from the CNA/CISA data inside the CVE record)
  CISA KEV      CVEs exploited in the wild right now
  FIRST EPSS    probability (%) that a CVE gets exploited in the next 30 days

Ranking (--sort risk, default): CISA KEV first, then EPSS, then CVSS score.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CIRCL_URL = "https://vulnerability.circl.lu/api/vulnerability"
SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
COLORS = {"CRITICAL": "1;31", "HIGH": "31", "MEDIUM": "33", "LOW": "34"}
NO_DESC = {"", "no description provided"}


class SourceError(Exception):
    pass


def http_json(url, headers=None, body=None, retries=3):
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"User-Agent": "cve-checker/1.0", **({"Content-Type": "application/json"} if data else {}),
            **(headers or {})}
    host = urllib.parse.urlparse(url).netloc
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data, hdrs), timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503) and attempt < retries - 1:  # rate limited / busy
                time.sleep(10 * (attempt + 1))
                continue
            raise SourceError(f"{host} returned HTTP {e.code} {e.reason}")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            if attempt < retries - 1:
                time.sleep(3)
                continue
            raise SourceError(f"cannot read {host}: {getattr(e, 'reason', e)}")


def warn(msg):
    print(f"warning: {msg}", file=sys.stderr)


def severity_of(score):
    if score is None:
        return ""
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "NONE"


# ---------------------------------------------------------------- NVD
def fetch_nvd(start, end, keyword, api_key):
    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.7 if api_key else 6.5  # stay under the rate limit when paging
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {"pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt), "resultsPerPage": 2000}
    if keyword:
        params["keywordSearch"] = keyword
    items, index = [], 0
    while True:
        params["startIndex"] = index
        data = http_json(f"{NVD_URL}?{urllib.parse.urlencode(params)}", headers)
        items += [v["cve"] for v in data.get("vulnerabilities", [])]
        index += data.get("resultsPerPage", 0)
        if index >= data.get("totalResults", 0) or not data.get("resultsPerPage"):
            return items
        time.sleep(delay)


def from_nvd(cve):
    score, severity = None, ""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            score = m["cvssData"]["baseScore"]
            severity = (m["cvssData"].get("baseSeverity") or m.get("baseSeverity") or severity_of(score)).upper()
            break
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    return {"id": cve["id"], "published": cve["published"][:10], "score": score, "severity": severity,
            "description": " ".join(desc.split()), "status": cve.get("vulnStatus", ""), "sources": ["NVD"]}


# ---------------------------------------------------------------- CIRCL
def from_circl(rec):
    """Build a row from a CVE JSON 5 record (CIRCL serves these)."""
    meta = rec.get("cveMetadata", {})
    containers = rec.get("containers", {})
    blocks = [containers.get("cna", {})] + containers.get("adp", [])
    score = severity = None
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        for b in blocks:
            for m in b.get("metrics", []):
                if key in m and m[key].get("baseScore") is not None:
                    score = m[key]["baseScore"]
                    severity = (m[key].get("baseSeverity") or severity_of(score)).upper()
                    break
            if score is not None:
                break
        if score is not None:
            break
    cna = containers.get("cna", {})
    desc = next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
    desc = " ".join(desc.split()) or cna.get("title", "")
    return {"id": meta.get("cveId", ""), "published": meta.get("datePublished", "")[:10], "score": score,
            "severity": severity or "", "description": desc, "status": meta.get("state", ""), "sources": ["CIRCL"]}


def fetch_circl(start):
    """The newest CVE records (CIRCL's feed holds only the ~30 most recent)."""
    out = [from_circl(r) for r in http_json(f"{CIRCL_URL}/last/cvelistv5/100")
           if r.get("cveMetadata", {}).get("state") == "PUBLISHED"]
    return [r for r in out if r["id"] and r["published"] >= f"{start:%Y-%m-%d}"]


def fill_from_circl(rows):
    """Give unscored / undescribed NVD rows a score and text from the CVE record (CNA/CISA data)."""
    need = [r for r in rows if r["score"] is None or r["description"].lower() in NO_DESC][:500]
    for i in range(0, len(need), 100):
        batch = {r["id"]: r for r in need[i:i + 100]}
        data = http_json(f"{CIRCL_URL}/bulk", body={"ids": list(batch)})
        for item in data.get("data", []):
            src = from_circl(item.get("vulnerability", {}))
            row = batch.get(item.get("id"))
            if not row:
                continue
            if row["score"] is None and src["score"] is not None:
                row.update(score=src["score"], severity=src["severity"])
                row["sources"].append("CIRCL")
            if row["description"].lower() in NO_DESC and src["description"]:
                row["description"] = src["description"]


# ---------------------------------------------------------------- KEV / EPSS
def fetch_kev():
    return {v["cveID"] for v in http_json(KEV_URL).get("vulnerabilities", [])}


def fetch_epss(ids):
    scores = {}
    for i in range(0, len(ids), 100):
        data = http_json(f"{EPSS_URL}?cve={','.join(ids[i:i + 100])}")
        for d in data.get("data", []):
            scores[d["cve"]] = float(d["epss"])
    return scores


# ---------------------------------------------------------------- output
def colorize(text, severity):
    if not sys.stdout.isatty() or "NO_COLOR" in os.environ or severity not in COLORS:
        return text
    return f"\033[{COLORS[severity]}m{text}\033[0m"


def short(text, limit):
    return text if len(text) <= limit else text[:limit - 1] + "…"


def print_table(rows, width):
    headers = ["CVE", "PUBLISHED", "SCORE", "SEVERITY", "EPSS", "KEV", "DESCRIPTION"]
    cells = [[r["id"], r["published"], "-" if r["score"] is None else str(r["score"]), r["severity"] or "-",
              "-" if r.get("epss") is None else f"{r['epss'] * 100:.1f}%", "YES" if r["kev"] else "",
              short(r["description"], width)] for r in rows]
    widths = [max(len(x) for x in col) for col in zip(headers, *cells)]
    line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def fmt(vals, severity=""):
        out = []
        for i, (v, w) in enumerate(zip(vals, widths)):
            pad = v.ljust(w)
            out.append(" " + (colorize(pad, severity) if i in (2, 3) else pad) + " ")
        return "|" + "|".join(out) + "|"

    print(line, fmt(headers), line, sep="\n")
    for c, r in zip(cells, rows):
        print(fmt(c, r["severity"]))
    print(line)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-d", "--days", type=int, default=3, help="CVEs published in the last N days, 1-120 (default 3)")
    p.add_argument("-k", "--keyword", help="only CVEs whose text mentions this word")
    p.add_argument("-s", "--severity", choices=["low", "medium", "high", "critical"], help="minimum severity")
    p.add_argument("--min-score", type=float, help="minimum CVSS base score, e.g. 7.5")
    p.add_argument("--kev", action="store_true", help="only CVEs in CISA's Known Exploited Vulnerabilities list")
    p.add_argument("--source", choices=["nvd", "circl", "both"], default="both", help="data source (default both)")
    p.add_argument("--no-epss", action="store_true", help="skip the EPSS lookup")
    p.add_argument("-n", "--limit", type=int, default=50, help="max rows to show (default 50, 0 = all)")
    p.add_argument("--sort", choices=["risk", "score", "epss", "date"], default="risk",
                   help="risk = KEV, then EPSS, then score (default)")
    p.add_argument("--width", type=int, default=70, help="description width in the table (default 70)")
    p.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = p.parse_args()
    if not 1 <= args.days <= 120:
        p.error("--days must be between 1 and 120 (NVD limit for one query)")

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)
    print(f"Fetching CVEs published since {start:%Y-%m-%d %H:%M} UTC ...", file=sys.stderr)

    rows, failures = {}, []
    if args.source in ("nvd", "both"):
        try:
            for c in fetch_nvd(start, end, args.keyword, os.environ.get("NVD_API_KEY")):
                rows[c["id"]] = from_nvd(c)
        except SourceError as e:
            failures.append(f"NVD: {e}")
    if args.source in ("circl", "both"):
        try:
            kw = args.keyword.lower() if args.keyword else None
            for r in fetch_circl(start):
                if kw and kw not in (r["description"] + r["id"]).lower():
                    continue
                if r["id"] in rows:
                    rows[r["id"]]["sources"].append("CIRCL")
                else:
                    rows[r["id"]] = r
        except SourceError as e:
            failures.append(f"CIRCL: {e}")
    if failures and not rows:
        sys.exit("error: " + "; ".join(failures))
    for f in failures:
        warn(f"{f} (continuing with the other source)")
    rows = list(rows.values())

    if args.source != "nvd":
        try:
            fill_from_circl(rows)
        except SourceError as e:
            warn(f"CIRCL score lookup skipped: {e}")
    try:
        kev = fetch_kev()
    except SourceError as e:
        if args.kev:
            sys.exit(f"error: {e}")
        warn(f"KEV list skipped: {e}")
        kev = set()
    for r in rows:
        r["kev"] = r["id"] in kev
        r["url"] = f"https://nvd.nist.gov/vuln/detail/{r['id']}"

    if args.severity:
        rows = [r for r in rows if SEVERITY_RANK.get(r["severity"], 0) >= SEVERITY_RANK[args.severity.upper()]]
    if args.min_score is not None:
        rows = [r for r in rows if r["score"] is not None and r["score"] >= args.min_score]
    if args.kev:
        rows = [r for r in rows if r["kev"]]

    epss = {}
    if not args.no_epss and rows:
        try:
            epss = fetch_epss([r["id"] for r in rows])
        except SourceError as e:
            warn(f"EPSS skipped: {e}")
    for r in rows:
        r["epss"] = epss.get(r["id"])

    keys = {"risk": lambda r: (r["kev"], r["epss"] or 0, r["score"] or -1),
            "score": lambda r: (r["kev"], r["score"] or -1, r["epss"] or 0),
            "epss": lambda r: (r["epss"] or 0, r["score"] or -1),
            "date": lambda r: (r["published"], r["id"])}
    rows.sort(key=keys[args.sort], reverse=True)

    total = len(rows)
    if args.limit:
        rows = rows[:args.limit]

    if args.json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print("No matching CVEs.")
        return
    print_table(rows, args.width)
    exploited = sum(r["kev"] for r in rows)
    print(f"Showing {len(rows)} of {total} matching CVEs"
          + (f", {exploited} actively exploited (KEV)" if exploited else "")
          + ". EPSS = chance of exploitation in the next 30 days. Details: https://nvd.nist.gov/vuln/detail/<CVE-ID>")


if __name__ == "__main__":
    main()
