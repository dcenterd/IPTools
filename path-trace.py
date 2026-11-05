#!/usr/bin/env python3
"""Live traceroute with a colored progress bar pinned to the bottom line.

Probe types (none need root; Linux):
  icmp  system `ping` with a limited TTL
  udp   UDP datagrams, ICMP replies read through IP_RECVERR
  tcp   non-blocking TCP SYNs, ICMP replies read through IP_RECVERR

Extras:
  --asn      ASN / org / country per hop (Team Cymru whois)
  --mtu      path MTU discovery (DF pings, binary search)
  --compare  compare ICMP/UDP/TCP paths to one host, or several hosts side by side
  --live     keep probing every hop and show live stats + sparklines
  --ping     ICMP (or TCP with -T) ping with stats, instead of tracing
  --scan     TCP/UDP port check, instead of tracing
  --open     find open ports on both TCP and UDP (confirmed-open only)

Usage: path-trace.py <host> [host ...] [-P icmp|udp|tcp | -u | -T] [--port N]
                     [--asn] [--mtu] [--compare [--protos icmp,udp,tcp]] [--live]
                     [--ping [-c N]] [--scan [PORTS] [--scan-proto tcp,udp] | --open]
"""
import argparse
import errno
import ipaddress
import math
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GREEN, YELLOW = "\033[31m", "\033[32m", "\033[33m"
BLUE, MAGENTA, CYAN = "\033[34m", "\033[35m", "\033[36m"

IP_RECVERR = 11
SO_EE_ORIGIN_ICMP = 2
UDP_BASE_PORT = 33434
SCAN_TIMEOUT = 1.0   # seconds per port
SCAN_THREADS = 100   # concurrent port probes

FROM_RE = re.compile(r"[Ff]rom\s+(\d+\.\d+\.\d+\.\d+)")
MTU_RE = re.compile(r"mtu\s*=\s*(\d+)")


# --------------------------------------------------------------------------- probes

def probe(target, ttl, timeout):
    """ICMP echo via system ping. Returns (ip or None, rtt_ms or None, reached)."""
    start = time.monotonic()
    try:
        out = subprocess.run(
            ["ping", "-n", "-c", "1", "-t", str(ttl), "-W", str(timeout), target],
            capture_output=True, text=True, timeout=timeout + 2,
        ).stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None, None, False
    rtt = (time.monotonic() - start) * 1000
    m = FROM_RE.search(out)
    if not m:
        return None, None, False
    reached = "bytes from" in out and "exceeded" not in out
    return m.group(1), rtt, reached


def read_icmp_error(sock):
    """Pop one ICMP error off the socket error queue -> (ip, type, code) or None."""
    try:
        _, anc, _, _ = sock.recvmsg(512, 512, socket.MSG_ERRQUEUE)
    except OSError:
        return None
    for level, ctype, data in anc:
        if level == socket.SOL_IP and ctype == IP_RECVERR and len(data) >= 24:
            _, origin, icmp_type, icmp_code = struct.unpack_from("=IBBB", data, 0)
            if origin == SO_EE_ORIGIN_ICMP:
                return socket.inet_ntoa(data[20:24]), icmp_type, icmp_code
    return None


def probe_udp(target, ttl, timeout, port):
    """UDP probe. Returns (ip or None, rtt_ms or None, reached)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        sock.setsockopt(socket.SOL_IP, IP_RECVERR, 1)
        start = time.monotonic()
        sock.sendto(b"path-trace", (target, port))
        poller = select.poll()
        poller.register(sock, select.POLLERR | select.POLLIN)
        if not poller.poll(timeout * 1000):
            return None, None, False
        rtt = (time.monotonic() - start) * 1000
        err = read_icmp_error(sock)
        if not err:
            return None, None, False
        ip, icmp_type, icmp_code = err
        # type 3 / code 3 = port unreachable: the destination answered
        return ip, rtt, icmp_type == 3 and icmp_code == 3
    except OSError:
        return None, None, False
    finally:
        sock.close()


def probe_tcp(target, ttl, timeout, port):
    """TCP SYN probe. Hop IPs come from ICMP time-exceeded; the target answers with
    SYN/ACK (connected) or RST (refused) - both count as reached."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        sock.setsockopt(socket.SOL_IP, IP_RECVERR, 1)
        start = time.monotonic()
        sock.connect_ex((target, port))
        poller = select.poll()
        poller.register(sock, select.POLLOUT | select.POLLERR | select.POLLIN)
        if not poller.poll(timeout * 1000):
            return None, None, False
        rtt = (time.monotonic() - start) * 1000
        err = read_icmp_error(sock)
        if err:
            return err[0], rtt, False
        if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) in (0, errno.ECONNREFUSED):
            return target, rtt, True
        return None, None, False
    except OSError:
        return None, None, False
    finally:
        sock.close()


def make_sender(proto, target, args):
    """Return send(ttl, i) -> (ip, rtt, reached) for the chosen protocol."""
    if proto == "udp":
        return lambda ttl, i: probe_udp(target, ttl, args.timeout,
                                        UDP_BASE_PORT + (ttl - 1) * args.probes + i)
    if proto == "tcp":
        return lambda ttl, i: probe_tcp(target, ttl, args.timeout, args.port)
    return lambda ttl, i: probe(target, ttl, args.timeout)


# --------------------------------------------------------------------------- helpers

def rtt_color(ms):
    return GREEN if ms < 50 else YELLOW if ms < 150 else RED


def reverse(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


_asn_cache = {}
_asn_ok = True


def asn_lookup(ip):
    """'AS15169 GOOGLE, US' via Team Cymru whois, 'private' for non-global space."""
    global _asn_ok
    if ip in _asn_cache:
        return _asn_cache[ip]
    try:
        if not ipaddress.ip_address(ip).is_global:
            return "private"
    except ValueError:
        return ""
    if not _asn_ok:
        return ""
    text = ""
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=3) as s:
            s.sendall(f" -v {ip}\r\n".encode())
            data = b""
            while chunk := s.recv(4096):
                data += chunk
        for line in data.decode(errors="replace").splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 7 and parts[0].isdigit():
                text = f"AS{parts[0]} {parts[6]}"
    except OSError:
        _asn_ok = False
    _asn_cache[ip] = text
    return text


def hop_info(ip, args):
    """Colored 'hostname  [ASN org, CC]' text for a hop."""
    if not ip:
        return ""
    host = "" if args.no_dns else reverse(ip)
    out = f"{CYAN}{host}{RESET}" if host else ""
    if args.asn:
        asn = asn_lookup(ip)
        if asn:
            out += f"  {DIM}[{RESET}{BLUE}{asn}{RESET}{DIM}]{RESET}"
    return out


def bar(done, total, width, label):
    frac = min(1.0, done / total) if total else 0
    filled = int(width * frac)
    color = RED if frac < 0.34 else YELLOW if frac < 0.67 else GREEN
    return (f"{BOLD}{label}{RESET} [{color}{'█' * filled}{DIM}{'░' * (width - filled)}{RESET}] "
            f"{color}{frac * 100:5.1f}%{RESET} {DIM}{done}/{total}{RESET}")


def bar_width():
    return max(10, min(40, shutil.get_terminal_size().columns - 40))


# --------------------------------------------------------------------------- tracing

def trace_path(target, proto, args, on_hop=None):
    """Trace one path. Returns (hops, reached_hop). Each hop is a dict with
    ttl, results [(ip, rtt, reached)...], ip (majority vote) and avg rtt."""
    send = make_sender(proto, target, args)
    hops, reached_hop = [], None
    with ThreadPoolExecutor(max_workers=args.probes) as pool:
        for ttl in range(1, args.max_hops + 1):
            results = list(pool.map(lambda i: send(ttl, i), range(args.probes)))
            ips = [r[0] for r in results if r[0]]
            rtts = [r[1] for r in results if r[1] is not None]
            hop = {
                "ttl": ttl, "results": results,
                "ip": max(set(ips), key=ips.count) if ips else None,
                "avg": sum(rtts) / len(rtts) if rtts else None,
            }
            hops.append(hop)
            if on_hop:
                on_hop(hop)
            if any(r[2] for r in results):
                reached_hop = ttl
                break
    return hops, reached_hop


def proto_label(proto, args):
    return f"TCP:{args.port}" if proto == "tcp" else proto.upper()


def run_single(args, host, target):
    """Normal trace: hop lines scroll, colored progress bar stays on the bottom line."""
    w = bar_width()
    print(f"{BOLD}{CYAN}Tracing{RESET} {host} ({MAGENTA}{target}{RESET}) "
          f"via {YELLOW}{proto_label(args.proto, args)}{RESET}, max {args.max_hops} hops\n")
    print(f"{DIM}{'HOP':>3}  {'IP':<16} {'RTTs (ms)':<30} HOST{' / ASN' if args.asn else ''}{RESET}")

    def on_hop(hop):
        rtts = "  ".join(
            f"{rtt_color(r[1])}{r[1]:6.1f}{RESET}" if r[0] else f"{RED}     *{RESET}"
            for r in hop["results"])
        ip = hop["ip"]
        ip_txt = f"{MAGENTA}{ip:<16}{RESET}" if ip else f"{RED}{'*':<16}{RESET}"
        line = f"{BOLD}{hop['ttl']:>3}{RESET}  {ip_txt} {rtts}   {hop_info(ip, args)}"
        # erase bar, print hop line (scrolls up), redraw bar underneath
        sys.stdout.write("\r\033[K" + line + "\n" + bar(hop["ttl"], args.max_hops, w, "Tracing"))
        sys.stdout.flush()

    sys.stdout.write(bar(0, args.max_hops, w, "Tracing"))
    hops, reached = trace_path(target, args.proto, args, on_hop)
    sys.stdout.write("\r\033[K" + bar(args.max_hops if reached else len(hops), args.max_hops,
                                      w, "Done   " if reached else "Gave up") + "\n")
    if reached:
        print(f"\n{GREEN}{BOLD}Reached {target} in {reached} hops.{RESET}")
    else:
        print(f"\n{RED}Did not reach {target} within {args.max_hops} hops.{RESET}")
    return hops, reached


# --------------------------------------------------------------------------- compare

def run_compare(args, targets):
    """Trace several (label, target, proto) jobs in parallel; print them side by side."""
    if len(targets) > 1:
        jobs = [(h, t, args.proto) for h, t in targets]
    else:
        t = targets[0][1]
        protos = [p.strip() for p in args.protos.split(",") if p.strip()]
        bad = [p for p in protos if p not in ("icmp", "udp", "tcp")]
        if bad:
            sys.exit(f"error: unknown protocol(s) in --protos: {', '.join(bad)}")
        jobs = [(proto_label(p, args), t, p) for p in protos]

    w = bar_width()
    total = args.max_hops * len(jobs)
    done = [0]
    lock = threading.Lock()
    kind = "targets" if len(targets) > 1 else "protocols"
    print(f"{BOLD}{CYAN}Comparing{RESET} {len(jobs)} {kind}: "
          f"{', '.join(MAGENTA + j[0] + RESET for j in jobs)}\n")

    def draw(label="Comparing"):
        sys.stdout.write("\r\033[K" + bar(done[0], total, w, label))
        sys.stdout.flush()

    def run_job(job):
        def on_hop(_hop):
            with lock:
                done[0] += 1
                draw()
        hops, reached = trace_path(job[1], job[2], args, on_hop)
        with lock:  # unused hops (path shorter than max) count as complete
            done[0] += args.max_hops - len(hops)
            draw()
        return hops, reached

    draw()
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        results = list(pool.map(run_job, jobs))
    done[0] = total
    draw("Done     ")
    print("\n")

    cw = 24
    print(f"{DIM}{'HOP':>3}   " + "".join(f"{j[0][:cw - 2]:<{cw}}" for j in jobs) + RESET)
    first_diff = None
    for i in range(max(len(r[0]) for r in results)):
        cells, ips = [], set()
        for hops, _reached in results:
            if i < len(hops):
                ip, avg = hops[i]["ip"], hops[i]["avg"]
                if ip:
                    ips.add(ip)
                    cells.append(f"{MAGENTA}{ip:<15}{RESET}{rtt_color(avg)}{avg:7.1f}{RESET} ")
                else:
                    cells.append(f"{RED}{'*':<15}{'':7}{RESET} ")
            else:
                cells.append(f"{DIM}{'-':<15}{'':7}{RESET} ")
        differs = len(ips) > 1
        if differs and first_diff is None:
            first_diff = i + 1
        mark = f"{YELLOW}≠{RESET}" if differs else " "
        print(f"{BOLD}{i + 1:>3}{RESET} {mark} " + "".join(c + " " for c in cells))

    print()
    for (label, _t, _p), (hops, reached) in zip(jobs, results):
        if reached:
            avg = hops[-1]["avg"]
            avg_txt = f"{avg:.1f} ms" if avg is not None else "-"
            print(f"  {BOLD}{label:<14}{RESET} {GREEN}reached in {reached} hops{RESET}, final hop {avg_txt}")
        else:
            print(f"  {BOLD}{label:<14}{RESET} {RED}not reached within {args.max_hops} hops{RESET}")
    if len(targets) == 1:
        if first_diff:
            print(f"\n{YELLOW}Paths first diverge at hop {first_diff}.{RESET}")
        else:
            print(f"\n{GREEN}All protocols took the same path.{RESET}")


# --------------------------------------------------------------------------- MTU

def discover_mtu(args, target, hop_ips):
    """Path MTU via DF pings and binary search over ICMP payload size."""
    hdr = 28  # 20 IP + 8 ICMP
    w = bar_width()
    bottleneck = None

    def try_size(payload):
        try:
            p = subprocess.run(
                ["ping", "-n", "-c", "1", "-M", "do", "-s", str(payload), "-W", str(args.timeout), target],
                capture_output=True, text=True, timeout=args.timeout + 3)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False, None, None
        out = p.stdout + p.stderr
        m, f = MTU_RE.search(out), FROM_RE.search(out)
        return p.returncode == 0, int(m.group(1)) if m else None, f.group(1) if f else None

    print(f"\n{BOLD}{CYAN}Path MTU discovery{RESET} to {MAGENTA}{target}{RESET}")
    if not try_size(16)[0]:
        print(f"{RED}No reply to small DF pings; cannot determine MTU (ICMP blocked?).{RESET}")
        return None
    lo, hi = 16, 8972 + 1  # lo = known good payload, hi = known/assumed bad
    span0 = math.log2(hi - lo)
    sys.stdout.write(bar(0, 100, w, "MTU    "))
    candidates = [1472, 8972]  # Ethernet, then jumbo
    while hi - lo > 1:
        if candidates and lo < candidates[0] < hi:
            mid = candidates.pop(0)
        else:
            candidates = [c for c in candidates if lo < c < hi]
            mid = (lo + hi) // 2
        ok, hint, frm = try_size(mid)
        if ok:
            lo = mid
        else:
            hi = mid
            if hint and frm:  # a router told us its MTU: remember who, jump straight to it
                bottleneck = frm
                if lo < hint - hdr < hi:
                    candidates.insert(0, hint - hdr)
        sys.stdout.write("\r\033[K" + f"  {mid + hdr:>5} B  " +
                         (f"{GREEN}ok{RESET}" if ok else f"{RED}too big / no reply{RESET}") + "\n" +
                         bar(round(100 * (1 - math.log2(max(hi - lo, 1)) / span0)), 100, w, "MTU    "))
        sys.stdout.flush()
    sys.stdout.write("\r\033[K")
    mtu = lo + hdr
    note = " (jumbo frames)" if mtu > 1500 else ""
    print(f"{GREEN}{BOLD}Path MTU: {mtu} bytes{RESET}{note}  {DIM}(max payload {lo}){RESET}")
    if bottleneck and mtu < 1500:
        where = f"hop {hop_ips.index(bottleneck) + 1} " if bottleneck in hop_ips else ""
        print(f"{YELLOW}Limited by {where}{bottleneck}{RESET}")
    return mtu


# --------------------------------------------------------------------------- live

SPARKS = "▁▂▃▄▅▆▇█"


def sparkline(values, width):
    vals = list(values)[-width:]
    nums = [v for v in vals if v is not None]
    if not nums:
        return " " * width
    lo, hi = min(nums), max(nums)
    out = []
    for v in vals:
        if v is None:
            out.append(f"{RED}×{RESET}")
        else:
            i = 0 if hi == lo else int((v - lo) / (hi - lo) * (len(SPARKS) - 1))
            out.append(f"{rtt_color(v)}{SPARKS[i]}{RESET}")
    return " " * (width - len(vals)) + "".join(out)


def run_live(args, target, hop_ips, send):
    """Repeatedly probe every hop of the discovered path and draw stats."""
    n = len(hop_ips)
    cols = shutil.get_terminal_size().columns
    width = max(20, min(cols - 12, 100))
    spark_w = max(8, min(24, cols - 75))
    hist = [deque(maxlen=width) for _ in range(n)]
    sent, recv = [0] * n, [0] * n
    total, best, worst, last = [0.0] * n, [None] * n, [None] * n, [None] * n
    names = [hop_info(ip, args) for ip in hop_ips]
    pool = ThreadPoolExecutor(max_workers=n)
    t0 = time.monotonic()

    def render(rnd):
        out = [f"{BOLD}{CYAN}LIVE trace{RESET} to {MAGENTA}{target}{RESET} via "
               f"{YELLOW}{proto_label(args.proto, args)}{RESET}  {DIM}round {rnd}  "
               f"elapsed {time.monotonic() - t0:5.0f}s  Ctrl+C to quit{RESET}", "",
               f"{DIM}{'HOP':>3}  {'IP':<16} {'LOSS':>6} {'LAST':>7} {'AVG':>7} "
               f"{'BEST':>7} {'WRST':>7}  {'HISTORY':<{spark_w}}  HOST{RESET}"]
        num = lambda v: f"{rtt_color(v)}{v:7.1f}{RESET}" if v is not None else f"{DIM}{'-':>7}{RESET}"
        for i in range(n):
            ip = hop_ips[i]
            loss = 100 * (sent[i] - recv[i]) / sent[i] if sent[i] else 0
            lc = GREEN if loss == 0 else YELLOW if loss < 20 else RED
            avg = total[i] / recv[i] if recv[i] else None
            ip_txt = f"{MAGENTA}{ip:<16}{RESET}" if ip else f"{RED}{'*':<16}{RESET}"
            out.append(f" {i + 1:>2}  {ip_txt} {lc}{loss:5.1f}%{RESET} {num(last[i])} "
                       f"{num(avg)} {num(best[i])} {num(worst[i])}  "
                       f"{sparkline(hist[i], spark_w)}  {names[i]}")
        sys.stdout.write("\033[H" + "".join(l + "\033[K\n" for l in out[:-1]) + out[-1] + "\033[K\033[J")
        sys.stdout.flush()

    sys.stdout.write("\033[?1049h\033[?25l")  # alt screen, hide cursor
    rnd = 0
    try:
        while not args.count or rnd < args.count:
            rnd += 1
            futs = {pool.submit(send, i + 1, 0): i for i in range(n)}
            for f in as_completed(futs):
                i = futs[f]
                _, rtt, _ = f.result()
                sent[i] += 1
                hist[i].append(rtt)
                last[i] = rtt
                if rtt is not None:
                    recv[i] += 1
                    total[i] += rtt
                    best[i] = rtt if best[i] is None else min(best[i], rtt)
                    worst[i] = rtt if worst[i] is None else max(worst[i], rtt)
                render(rnd)
            deadline = time.monotonic() + args.interval
            while time.monotonic() < deadline and (not args.count or rnd < args.count):
                time.sleep(0.05)
    except KeyboardInterrupt:
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        sys.stdout.write("\033[?25h\033[?1049l")
        sys.stdout.flush()
    # leave a final snapshot on the normal screen
    fmt = lambda v: f"{v:.1f}" if v is not None else "-"
    print(f"{BOLD}{CYAN}LIVE trace summary{RESET} for {target} ({rnd} rounds)")
    for i in range(n):
        loss = 100 * (sent[i] - recv[i]) / sent[i] if sent[i] else 0
        avg = fmt(total[i] / recv[i]) if recv[i] else "-"
        print(f"{i + 1:>3}  {hop_ips[i] or '*':<16} loss {loss:5.1f}%  avg {avg} ms  "
              f"best {fmt(best[i])} ms  worst {fmt(worst[i])} ms")


# --------------------------------------------------------------------------- ping

TIME_RE = re.compile(r"time[=<]([\d.]+)\s*ms")


def ping_icmp(target, timeout):
    """One real ICMP echo. Returns rtt_ms (from ping's own timing) or None."""
    try:
        p = subprocess.run(["ping", "-n", "-c", "1", "-W", str(timeout), target],
                           capture_output=True, text=True, timeout=timeout + 2)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    m = TIME_RE.search(p.stdout)
    return float(m.group(1)) if p.returncode == 0 and m else None


def run_ping(args, target):
    """Ping the target with ICMP (default) or TCP connects; live lines + bottom bar."""
    if args.proto == "udp":
        sys.exit("error: --ping supports icmp and tcp (use -T for a TCP ping)")
    tcp = args.proto == "tcp"
    kind = f"TCP:{args.port}" if tcp else "ICMP"
    w = bar_width()
    print(f"{BOLD}{CYAN}Ping{RESET} {MAGENTA}{target}{RESET} via {YELLOW}{kind}{RESET}, "
          f"{args.ping_count} probes\n")
    rtts, sent = [], 0
    sys.stdout.write(bar(0, args.ping_count, w, "Pinging"))
    try:
        for seq in range(1, args.ping_count + 1):
            t0 = time.monotonic()
            rtt = probe_tcp(target, 64, args.timeout, args.port)[1] if tcp else ping_icmp(target, args.timeout)
            sent += 1
            rtts.append(rtt)
            res = (f"{GREEN}reply{RESET} from {MAGENTA}{target}{RESET}  time {rtt_color(rtt)}{rtt:7.1f} ms{RESET}"
                   if rtt is not None else f"{RED}timeout{RESET}")
            sys.stdout.write("\r\033[K" + f"{DIM}seq {seq:>3}{RESET}  {res}\n"
                             + bar(seq, args.ping_count, w, "Pinging"))
            sys.stdout.flush()
            if seq < args.ping_count:
                time.sleep(max(0, args.interval - (time.monotonic() - t0)))
    except KeyboardInterrupt:
        pass
    sys.stdout.write("\r\033[K")
    ok = [r for r in rtts if r is not None]
    loss = 100 * (sent - len(ok)) / sent if sent else 0
    lc = GREEN if loss == 0 else YELLOW if loss < 20 else RED
    print(f"{BOLD}--- {target} ping statistics ---{RESET}")
    print(f"{sent} sent, {len(ok)} received, {lc}{loss:.1f}% loss{RESET}")
    if ok:
        avg = sum(ok) / len(ok)
        jitter = math.sqrt(sum((x - avg) ** 2 for x in ok) / len(ok))
        print(f"min {rtt_color(min(ok))}{min(ok):.1f}{RESET} / avg {rtt_color(avg)}{avg:.1f}{RESET} / "
              f"max {rtt_color(max(ok))}{max(ok):.1f}{RESET} / jitter {jitter:.1f} ms")
        print(sparkline(rtts, min(len(rtts), 60)))


# --------------------------------------------------------------------------- port scan

TOP_TCP = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
           1723, 3306, 3389, 5432, 5900, 8080, 8443]
TOP_UDP = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 4500, 5353]
UDP_PAYLOADS = {
    53: struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x00\x00\x01\x00\x01",  # DNS query for "."
    123: b"\x1b" + 47 * b"\x00",                                                       # NTP client request
}


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        try:
            a, b = int(lo), int(hi or lo)
        except ValueError:
            sys.exit(f"error: bad port spec '{part}'")
        if not (1 <= a <= b <= 65535):
            sys.exit(f"error: port out of range: '{part}'")
        ports.update(range(a, b + 1))
    return sorted(ports)


def scan_tcp(target, port, timeout):
    """-> (state, rtt_ms). open = handshake completed, closed = RST, filtered = no answer."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        start = time.monotonic()
        sock.connect_ex((target, port))
        poller = select.poll()
        poller.register(sock, select.POLLOUT | select.POLLERR)
        if not poller.poll(timeout * 1000):
            return "filtered", None
        rtt = (time.monotonic() - start) * 1000
        err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err == 0:
            return "open", rtt
        return ("closed", rtt) if err == errno.ECONNREFUSED else ("filtered", rtt)
    except OSError:
        return "filtered", None
    finally:
        sock.close()


def scan_udp(target, port, timeout, tries=2):
    """-> (state, rtt_ms). open = got a reply, closed = ICMP port unreachable,
    open|filtered = silence (UDP gives no handshake)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_IP, IP_RECVERR, 1)
        sock.connect((target, port))
        poller = select.poll()
        poller.register(sock, select.POLLIN | select.POLLERR)
        payload = UDP_PAYLOADS.get(port, b"\x00")
        for _ in range(tries):
            start = time.monotonic()
            sock.send(payload)
            events = poller.poll(timeout * 1000)
            if not events:
                continue
            rtt = (time.monotonic() - start) * 1000
            flags = events[0][1]
            if flags & select.POLLERR:
                err = read_icmp_error(sock)
                if err:
                    return ("closed" if err[1] == 3 and err[2] == 3 else "filtered"), rtt
                if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == errno.ECONNREFUSED:
                    return "closed", rtt
            elif flags & select.POLLIN:
                try:
                    sock.recv(2048)
                    return "open", rtt
                except OSError:
                    return "closed", rtt
        return "open|filtered", None
    except OSError:
        return "filtered", None
    finally:
        sock.close()


STATE_COLOR = {"open": GREEN, "closed": RED, "filtered": YELLOW, "open|filtered": YELLOW}


def service_name(port, proto):
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return ""


def run_scan(args, target):
    """TCP and/or UDP port check with a colored progress bar at the bottom."""
    protos = ["tcp", "udp"] if args.open else [p.strip() for p in (args.scan_proto or "tcp,udp").split(",") if p.strip()]
    if not protos or any(p not in ("tcp", "udp") for p in protos):
        sys.exit("error: --scan-proto must be tcp, udp or tcp,udp")
    jobs = []
    for proto in protos:
        ports = (TOP_TCP if proto == "tcp" else TOP_UDP) if args.scan == "top" else parse_ports(args.scan)
        jobs += [(proto, port) for port in ports]
    w = bar_width()
    print(f"{BOLD}{CYAN}Port scan{RESET} {MAGENTA}{target}{RESET}  "
          f"{YELLOW}{'+'.join(p.upper() for p in protos)}{RESET}, {len(jobs)} ports, "
          f"timeout {SCAN_TIMEOUT}s\n")
    print(f"{DIM}{'PORT':>11}  {'STATE':<14} {'RTT':>8}  SERVICE{RESET}")

    results, done = [], 0
    sys.stdout.write(bar(0, len(jobs), w, "Scanning"))
    pool = ThreadPoolExecutor(max_workers=max(1, min(SCAN_THREADS, len(jobs))))
    try:
        futs = {pool.submit((scan_tcp if proto == "tcp" else scan_udp), target, port,
                            SCAN_TIMEOUT): (proto, port) for proto, port in jobs}
        for f in as_completed(futs):
            proto, port = futs[f]
            state, rtt = f.result()
            done += 1
            results.append((proto, port, state, rtt))
            line = ""
            if state == "open" or (not args.open and state == "open|filtered") or args.show_closed:
                rtt_txt = f"{rtt:6.1f}ms" if rtt is not None else f"{'-':>8}"
                line = (f"{port:>7}/{proto:<3}  {STATE_COLOR[state]}{state:<14}{RESET} {rtt_txt}  "
                        f"{CYAN}{service_name(port, proto)}{RESET}\n")
            sys.stdout.write("\r\033[K" + line + bar(done, len(jobs), w, "Scanning"))
            sys.stdout.flush()
    except KeyboardInterrupt:
        pool.shutdown(wait=False, cancel_futures=True)
        sys.stdout.write("\r\033[K" + f"{YELLOW}Interrupted.{RESET}\n")
    else:
        pool.shutdown()
        sys.stdout.write("\r\033[K" + bar(len(jobs), len(jobs), w, "Done    ") + "\n")

    print(f"\n{BOLD}Summary{RESET}")
    for proto in protos:
        counts = {}
        for p, _port, st, _ in results:
            if p == proto:
                counts[st] = counts.get(st, 0) + 1
        parts = ", ".join(f"{STATE_COLOR[k]}{v} {k}{RESET}" for k, v in sorted(counts.items()))
        print(f"  {BOLD}{proto.upper():<4}{RESET} {parts or 'no results'}")
    opened = sorted((p, port) for p, port, st, _ in results if st == "open")
    if opened:
        print(f"  {GREEN}open:{RESET} " + ", ".join(f"{port}/{p}" for p, port in opened))
    if not args.open and any(st == "open|filtered" for _, _, st, _ in results):
        print(f"  {DIM}open|filtered = no reply (UDP services often stay silent, or a firewall drops it){RESET}")


# --------------------------------------------------------------------------- main

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        sys.exit(f"error: cannot resolve {host}: {e}")


def main():
    ap = argparse.ArgumentParser(description="Live traceroute with progress bar")
    ap.add_argument("hosts", nargs="+", metavar="host")
    ap.add_argument("-m", "--max-hops", type=int, default=30)
    ap.add_argument("-q", "--probes", type=int, default=3)
    ap.add_argument("-w", "--timeout", type=int, default=1, help="per-probe timeout (s)")
    ap.add_argument("-P", "--proto", choices=["icmp", "udp", "tcp"], default="icmp",
                    help="probe type (default: icmp)")
    ap.add_argument("-u", "--udp", action="store_const", const="udp", dest="proto",
                    help="shortcut for --proto udp")
    ap.add_argument("-T", "--tcp", action="store_const", const="tcp", dest="proto",
                    help="shortcut for --proto tcp")
    ap.add_argument("--port", type=int, default=443, help="TCP destination port (default 443)")
    ap.add_argument("-a", "--asn", action="store_true", help="show ASN / org / country per hop")
    ap.add_argument("--mtu", action="store_true", help="discover path MTU after tracing")
    ap.add_argument("--compare", action="store_true",
                    help="compare protocols for one host (several hosts are always compared)")
    ap.add_argument("--protos", default="icmp,udp,tcp", help="compare: protocols to run")
    ap.add_argument("--live", action="store_true",
                    help="after tracing, keep probing every hop and draw live stats")
    ap.add_argument("--interval", type=float, default=1.0, help="live mode: seconds between rounds")
    ap.add_argument("--count", type=int, default=0, help="live mode: stop after N rounds (0 = forever)")
    ap.add_argument("--ping", action="store_true",
                    help="ping the host (ICMP, or TCP connects with -T) instead of tracing")
    ap.add_argument("-c", "--ping-count", type=int, default=10, help="ping: number of probes")
    ap.add_argument("--scan", nargs="?", const="top", metavar="PORTS",
                    help="port check instead of tracing: 'top' (default), or e.g. 22,80,8000-8100")
    ap.add_argument("--scan-proto", default=None, metavar="PROTO",
                    help="scan: tcp, udp or tcp,udp (default); on its own it starts a scan of the common ports")
    ap.add_argument("--open", action="store_true",
                    help="scan for open ports on both TCP and UDP, listing only confirmed-open ones "
                         "(uses the common-port list unless --scan PORTS is given)")
    ap.add_argument("--show-closed", action="store_true", help="scan: also list closed/filtered ports")
    ap.add_argument("-n", "--no-dns", action="store_true", help="skip reverse DNS")
    args = ap.parse_args()

    if not shutil.which("ping"):
        sys.exit("error: `ping` not found")
    comparing = args.compare or len(args.hosts) > 1
    if comparing and (args.live or args.mtu):
        sys.exit("error: --live and --mtu cannot be combined with compare mode")

    targets = [(h, resolve(h)) for h in args.hosts]
    try:
        if (args.open or args.scan_proto or args.show_closed) and not args.scan:
            args.scan = "top"  # scan options on their own imply a scan
        if args.ping or args.scan:
            if len(targets) > 1:
                sys.exit("error: --ping/--scan take a single host")
            if args.ping:
                run_ping(args, targets[0][1])
            if args.scan:
                if args.ping:
                    print()
                run_scan(args, targets[0][1])
            return 0
        if comparing:
            run_compare(args, targets)
            return 0

        host, target = targets[0]
        hops, _reached = run_single(args, host, target)
        hop_ips = [h["ip"] for h in hops]
        if args.mtu:
            discover_mtu(args, target, hop_ips)
        if args.live and hops:
            time.sleep(1)
            run_live(args, target, hop_ips, make_sender(args.proto, target, args))
    except KeyboardInterrupt:
        sys.stdout.write("\r\033[K")
        print(f"{YELLOW}Interrupted.{RESET}")
        return 130


if __name__ == "__main__":
    sys.exit(main())
