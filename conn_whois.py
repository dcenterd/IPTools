#!/usr/bin/env python3
"""conn_whois.py - who are you connected to right now?

Lists the remote IPs of this machine's established TCP connections (and UDP peers with
--udp) with a short whois: origin AS, organisation, country and reverse DNS, plus the
programs holding the connections. One bulk whois query (Team Cymru) covers all IPs.
Standard library only; needs the `ss` command (iproute2) on Linux.

Usage: conn_whois.py [--all] [--udp] [--no-dns] [--json] [--sort conns|ip|asn]
"""
import argparse
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
CYAN, MAGENTA, BLUE, YELLOW = "\033[36m", "\033[35m", "\033[34m", "\033[33m"

PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')


def split_addr(s):
    """'1.2.3.4:443', '[2001:db8::1]:443' or '::ffff:1.2.3.4%eth0:443' -> (ip, port)."""
    host, _, port = s.rpartition(":")
    host = host.strip("[]").split("%")[0]
    if host.startswith("::ffff:") and "." in host:
        host = host[7:]
    return host, port


def read_connections(udp):
    if not shutil.which("ss"):
        sys.exit("error: `ss` not found (install iproute2)")
    proto = "-tnpH" if not udp else "-tunpH"
    cmd = ["ss", proto] + (["state", "established"] if not udp else [])
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.TimeoutExpired) as e:
        sys.exit("error: ss failed: %s" % e)
    conns = []
    for line in out.splitlines():
        f = line.split()
        if udp:                                  # udp rows: Netid State Recv Send Local Peer ...
            if len(f) < 6 or f[0] not in ("tcp", "udp") or (f[0] == "tcp" and f[1] != "ESTAB"):
                continue
            net, local, peer, rest = f[0], f[4], f[5], " ".join(f[6:])
        else:                                    # tcp rows: Recv Send Local Peer ...
            if len(f) < 4:
                continue
            net, local, peer, rest = "tcp", f[2], f[3], " ".join(f[4:])
        ip, port = split_addr(peer)
        if not ip or ip in ("*", "0.0.0.0", "::") or port in ("*", "0"):
            continue
        procs = sorted({m.group(1) for m in PROC_RE.finditer(rest)})
        conns.append({"net": net, "ip": ip, "port": port, "procs": procs})
    return conns


def is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def cymru_bulk(ips):
    """{ip: (asn, cc, name)} from one Team Cymru bulk whois query."""
    if not ips:
        return {}
    q = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    data = b""
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=8) as s:
            s.settimeout(15)
            s.sendall(q.encode())
            while chunk := s.recv(8192):
                data += chunk
    except OSError as e:
        print("warning: whois lookup failed (%s)" % e, file=sys.stderr)
        return {}
    res = {}
    for line in data.decode(errors="replace").splitlines():
        p = [x.strip() for x in line.split("|")]
        if len(p) >= 7 and p[0].isdigit():       # AS | IP | prefix | CC | registry | allocated | AS name
            name = re.sub(r",\s*[A-Z]{2}$", "", p[6])      # drop the trailing ", US" country suffix
            res[p[1]] = ("AS" + p[0], p[3], name)
    return res


def rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def main():
    ap = argparse.ArgumentParser(description="Short whois for the IPs you are connected to.")
    ap.add_argument("--all", action="store_true", help="also show private/local peers")
    ap.add_argument("--udp", action="store_true", help="include UDP peers (connected sockets)")
    ap.add_argument("--no-dns", action="store_true", help="skip reverse DNS")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--sort", choices=["conns", "ip", "asn"], default="conns", help="sort order (default conns)")
    args = ap.parse_args()

    conns = read_connections(args.udp)
    peers = defaultdict(lambda: {"conns": 0, "ports": set(), "procs": set()})
    for c in conns:
        p = peers[c["ip"]]
        p["conns"] += 1
        p["ports"].add(c["port"])
        p["procs"].update(c["procs"])
    if not args.all:
        peers = {ip: p for ip, p in peers.items() if is_public(ip)}
    if not peers:
        print("No %sconnections found." % ("" if args.all else "public "))
        return

    ips = sorted(peers)
    who = cymru_bulk([ip for ip in ips if is_public(ip)])
    names = {}
    if not args.no_dns:
        with ThreadPoolExecutor(max_workers=16) as pool:
            names = dict(zip(ips, pool.map(rdns, ips)))

    rows = []
    for ip in ips:
        p = peers[ip]
        asn, cc, org = who.get(ip, ("private" if not is_public(ip) else "-", "", ""))
        rows.append({"ip": ip, "conns": p["conns"], "ports": sorted(p["ports"], key=int),
                     "procs": sorted(p["procs"]), "asn": asn, "country": cc, "org": org,
                     "rdns": names.get(ip, "")})
    key = {"conns": lambda r: (-r["conns"], r["ip"]), "ip": lambda r: r["ip"], "asn": lambda r: (r["asn"], r["ip"])}
    rows.sort(key=key[args.sort])

    if args.json:
        print(json.dumps(rows, indent=2))
        return

    color = sys.stdout.isatty()
    c = (lambda code, s: code + s + RESET) if color else (lambda code, s: s)
    print(c(BOLD + CYAN, "Connected to %d remote IP%s (%d connections)" % (
        len(rows), "" if len(rows) == 1 else "s", sum(r["conns"] for r in rows))))
    print()
    w_ip = max(len(r["ip"]) for r in rows)
    hdr = "%-*s  %5s  %-9s %-2s  %-28s  %-16s  %s" % (w_ip, "REMOTE IP", "CONNS", "ASN", "CC", "ORG", "PROGRAM", "PORTS / REVERSE DNS")
    print(c(DIM, hdr))
    for r in rows:
        org = r["org"] if len(r["org"]) <= 28 else r["org"][:27] + "…"
        procs = ",".join(r["procs"]) if r["procs"] else "-"
        procs = procs if len(procs) <= 16 else procs[:15] + "…"
        ports = ",".join(r["ports"][:4]) + ("+" if len(r["ports"]) > 4 else "")
        tail = ports + ("  " + c(DIM, r["rdns"]) if r["rdns"] else "")
        print("%s  %5d  %s %-2s  %s  %-16s  %s" % (
            c(MAGENTA, "%-*s" % (w_ip, r["ip"])), r["conns"], c(BLUE, "%-9s" % r["asn"]),
            r["country"], "%-28s" % org, procs, tail))


if __name__ == "__main__":
    main()
