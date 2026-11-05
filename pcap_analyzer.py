#!/usr/bin/env python3
"""pcap_analyzer.py - text report for a packet capture (pcap / pcapng, optionally .gz).

Standard library only. Reads the capture once, streaming, and prints:
  summary, protocol hierarchy, then Layer 1 (capture/link), Layer 2 (Ethernet/ARP/VLAN),
  Layer 3 (IP/ICMP: top IPs and conversations), Layer 4 (TCP/UDP: ports, flags, handshakes,
  retransmissions), Layer 5-6 (TLS) and Layer 7 (DNS, HTTP, DHCP, banners), plus heuristic
  observations (scans, cleartext protocols, spoofing hints, ...).

Limits: packets are decoded one by one (no TCP reassembly), so L7 details are only
extracted when they sit in a single packet. The capture file has no real physical-layer
data; "Layer 1" shows what the capture itself records (link type, sizes, timing).

Usage: pcap_analyzer.py capture.pcap [options]

Output:
  -n, --top N        rows per top-list (default 10)
  --json             print JSON instead of text
  --html FILE        also write a self-contained HTML report with charts
  -o, --output FILE  write the plain-text report to this file as well
  -q, --quiet        with --html/-o/--extract: do not print the report to the terminal
  --whois            look up ASN/org/country of public IPs (sends them to whois.cymru.com)
  --color WHEN       auto (default), always or never; NO_COLOR is respected
  --no-trace         skip the flow-trace pass (it reads the capture a second time)

Filters (applied while reading; packet numbers stay those of the original file):
  --host IP          only packets to/from this IP (repeatable)
  --port N           only TCP/UDP packets using this port (repeatable)
  --proto P          only tcp, udp, icmp, icmpv6 or arp (repeatable)
  --flow A,B         only one conversation: IP:PORT,IP:PORT or [IPv6]:PORT,... (repeatable)
  --from TIME        start of window: +SECONDS after first packet, HH:MM:SS or 'YYYY-MM-DD HH:MM:SS' (UTC)
  --to TIME          end of window (same formats as --from)
  --extract FILE     write the packets that pass the filters to a new pcap (open in Wireshark)
"""
import argparse
import gzip
import hashlib
import html
import ipaddress
import json
import math
import os
import random
import re
import shlex
import shutil
import socket
import struct
import sys
import textwrap
from collections import Counter, defaultdict, deque, namedtuple
from datetime import datetime, timezone

SPARKS = "▁▂▃▄▅▆▇█"

LINKTYPES = {0: "NULL (BSD loopback)", 1: "Ethernet", 101: "Raw IP", 105: "IEEE 802.11",
             113: "Linux cooked (SLL)", 127: "802.11 + radiotap", 228: "Raw IPv4",
             229: "Raw IPv6", 276: "Linux cooked v2 (SLL2)"}
ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "VLAN", 0x88A8: "QinQ",
              0x8847: "MPLS", 0x88CC: "LLDP", 0x8863: "PPPoE disc", 0x8864: "PPPoE", 0x88E5: "MACsec"}
IPPROTOS = {1: "ICMP", 2: "IGMP", 4: "IP-in-IP", 6: "TCP", 17: "UDP", 41: "IPv6-in-IP", 47: "GRE",
            50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP"}
SERVICES = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp-server",
            68: "dhcp-client", 69: "tftp", 80: "http", 110: "pop3", 119: "nntp", 123: "ntp",
            135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
            161: "snmp", 162: "snmp-trap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
            514: "syslog", 546: "dhcpv6-c", 547: "dhcpv6-s", 587: "submission", 636: "ldaps",
            993: "imaps", 995: "pop3s", 1194: "openvpn", 1433: "mssql", 1723: "pptp", 1900: "ssdp",
            3306: "mysql", 3389: "rdp", 4500: "ipsec-nat-t", 5060: "sip", 5353: "mdns",
            5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
            27017: "mongodb", 51820: "wireguard"}
ICMP_TYPES = {0: "echo-reply", 3: "dest-unreachable", 4: "source-quench", 5: "redirect", 8: "echo-request",
              9: "router-adv", 10: "router-sol", 11: "time-exceeded", 12: "param-problem",
              13: "timestamp", 14: "timestamp-reply"}
ICMP6_TYPES = {1: "dest-unreachable", 2: "packet-too-big", 3: "time-exceeded", 4: "param-problem",
               128: "echo-request", 129: "echo-reply", 133: "router-sol", 134: "router-adv",
               135: "neighbor-sol", 136: "neighbor-adv", 137: "redirect", 143: "mldv2-report"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
             33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS",
             252: "AXFR", 255: "ANY"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
TLS_VERSIONS = {0x0300: "SSLv3", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
TCP_FLAG_NAMES = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
                  (0x40, "ECE"), (0x80, "CWR")]


# ------------------------------------------------------------------ readers

class CaptureError(Exception):
    pass


def open_capture(path):
    fh = open(path, "rb")
    magic = fh.read(2)
    fh.seek(0)
    if magic == b"\x1f\x8b":
        fh.close()
        fh = gzip.open(path, "rb")
    return fh


def read_exact(fh, n):
    b = fh.read(n)
    return b if len(b) == n else None


def iter_pcap(fh, meta):
    """Classic pcap. Yields (ts, caplen, origlen, linktype, data)."""
    hdr = read_exact(fh, 24)
    if not hdr or len(hdr) < 24:
        raise CaptureError("file too short for a pcap header")
    magic = hdr[:4]
    table = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
             b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
    if magic not in table:
        raise CaptureError("not a pcap file (bad magic)")
    end, res = table[magic]
    vmaj, vmin, _tz, _sig, snaplen, link = struct.unpack(end + "HHiIII", hdr[4:24])
    meta.update(format="pcap %d.%d (%s-endian)" % (vmaj, vmin, "little" if end == "<" else "big"),
                snaplen=snaplen, ts_precision="nanosecond" if res == 1e-9 else "microsecond",
                linktypes={link})
    while True:
        rh = read_exact(fh, 16)
        if not rh:
            return
        sec, frac, caplen, origlen = struct.unpack(end + "IIII", rh)
        if caplen > 0x4000000:
            meta["warning"] = "corrupt record header; capture truncated"
            return
        data = read_exact(fh, caplen)
        if data is None:
            meta["warning"] = "file ends in the middle of a packet"
            return
        yield sec + frac * res, caplen, origlen, link, data


def iter_pcapng(fh, meta):
    """pcapng. Yields (ts, caplen, origlen, linktype, data)."""
    ifaces = []  # (linktype, snaplen, ts resolution seconds)
    end = "<"
    meta.update(format="pcapng", linktypes=set(), snaplen=0, ts_precision="per-interface")
    while True:
        bh = read_exact(fh, 8)
        if not bh:
            return
        btype = struct.unpack("<I", bh[:4])[0]
        if bh[:4] == b"\x0a\x0d\x0d\x0a":  # section header: byte order from the magic
            rest = read_exact(fh, 4)
            if rest is None:
                return
            end = "<" if rest == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(end + "I", bh[4:8])[0]
            body = read_exact(fh, blen - 12)
            if body is None:
                return
            ifaces = []
            continue
        btype, blen = struct.unpack(end + "II", bh)
        if blen < 12 or blen > 0x4000000:
            meta["warning"] = "corrupt block; capture truncated"
            return
        body = read_exact(fh, blen - 8)
        if body is None:
            meta["warning"] = "file ends in the middle of a block"
            return
        body = body[:-4]  # trailing block length
        if btype == 1 and len(body) >= 8:  # interface description
            link, _r, snap = struct.unpack(end + "HHI", body[:8])
            res, off = 1e-6, 8
            while off + 4 <= len(body):
                code, ln = struct.unpack(end + "HH", body[off:off + 4])
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = body[off + 4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                off += 4 + ((ln + 3) & ~3)
            ifaces.append((link, snap, res))
            meta["linktypes"].add(link)
            meta["snaplen"] = max(meta["snaplen"], snap)
        elif btype == 6 and len(body) >= 20:  # enhanced packet
            ifid, hi, lo, caplen, origlen = struct.unpack(end + "IIIII", body[:20])
            link, _s, res = ifaces[ifid] if ifid < len(ifaces) else (1, 0, 1e-6)
            yield ((hi << 32) | lo) * res, caplen, origlen, link, body[20:20 + caplen]
        elif btype == 3 and len(body) >= 4 and ifaces:  # simple packet
            origlen = struct.unpack(end + "I", body[:4])[0]
            data = body[4:4 + origlen]
            yield None, len(data), origlen, ifaces[0][0], data


def iter_packets(fh, meta):
    head = fh.read(4)
    fh.seek(0)
    if head == b"\x0a\x0d\x0d\x0a":
        return iter_pcapng(fh, meta)
    return iter_pcap(fh, meta)


# ------------------------------------------------------------------ helpers

def mac_str(b):
    return ":".join("%02x" % x for x in b)


def ip4(b):
    return socket.inet_ntoa(b)


def ip6(b):
    return socket.inet_ntop(socket.AF_INET6, b)


def flags_str(f):
    s = [n for bit, n in TCP_FLAG_NAMES if f & bit]
    return "+".join(s) or "none"


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not a.is_global


def ip_class(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "?"
    if a.is_unspecified:
        return "unspecified"
    if str(a) == "255.255.255.255":
        return "broadcast"
    if a.is_multicast:
        return "multicast"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link-local"
    if a.is_private or not a.is_global:
        return "private"
    return "public"


def human_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%d B" % n if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024


def human_bps(bps):
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if bps < 1000 or unit == "Gbps":
            return "%.1f %s" % (bps, unit)
        bps /= 1000


def fmt_ts(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"


def printable(b, limit=80):
    s = b.decode("latin-1")
    s = "".join(c if 32 <= ord(c) < 127 else "." for c in s)
    return s[:limit]


def read_dns_name(data, off):
    labels, jumped, end, hops = [], False, off, 0
    while off < len(data) and hops < 20:
        ln = data[off]
        if ln == 0:
            if not jumped:
                end = off + 1
            return ".".join(labels), end
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((ln & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            off, jumped = ptr, True
            hops += 1
            continue
        labels.append(data[off + 1:off + 1 + ln].decode("latin-1"))
        off += 1 + ln
        if not jumped:
            end = off
    return None, end


# ------------------------------------------------------------------ analysis helpers

MASK32 = 0xFFFFFFFF
GREASE = {0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
          0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA}
Finding = namedtuple("Finding", "sev text filt pkts total")


def before(a, b):
    """True if TCP sequence number a is before b (32-bit wraparound)."""
    return ((a - b) & MASK32) > 0x80000000


def pctl(vals, p):
    """p-th percentile of a sorted list (linear interpolation)."""
    if not vals:
        return None
    k = (len(vals) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(vals) - 1)
    return vals[f] + (vals[c] - vals[f]) * (k - f)


def lat_stats(samples):
    """samples in ms -> (n, min, median, p95, max) or None."""
    if not samples:
        return None
    v = sorted(samples)
    return len(v), v[0], pctl(v, 50), pctl(v, 95), v[-1]


def fmt_ms(v):
    if v is None:
        return "-"
    if v >= 1000:
        return "%.2f s" % (v / 1000.0)
    return "%.1f ms" % v if v < 100 else "%.0f ms" % v


def flow_filter(a, b, proto="tcp"):
    """Wireshark display filter for one conversation between endpoints (ip, port)."""
    fam = "ipv6" if ":" in a[0] else "ip"
    return "%s.addr==%s && %s.addr==%s && %s.port==%d && %s.port==%d" % (fam, a[0], fam, b[0], proto, a[1], proto, b[1])


class TcpFlow:
    """State of one TCP connection: handshake, RTT samples, retransmissions, dup-ACKs, windows, options."""
    __slots__ = ("ep", "first", "last", "pkts", "bytes", "payload", "syn", "synack", "hsack", "rtts",
                 "retrans", "ooo", "dupack", "zwin", "rst", "fin", "closed", "rst_by", "max_seg", "retx_big",
                 "nxt", "seen", "unacked", "last_ack", "last_win", "mss", "ws", "sack", "tsopt", "ecn",
                 "established", "pk", "sni", "idx", "n0")

    def __init__(self, client, server, idx=0):
        self.ep = (client, server)
        self.first = self.last = None
        self.pkts, self.bytes, self.payload = [0, 0], [0, 0], [0, 0]
        self.syn = self.synack = self.hsack = None
        self.rtts = ([], [])
        self.retrans = self.ooo = self.dupack = self.zwin = self.rst = self.fin = 0
        self.closed = self.rst_by = None
        self.max_seg = self.retx_big = 0
        self.nxt = [None, None]
        self.seen = (set(), set())
        self.unacked = ({}, {})
        self.last_ack = [None, None]
        self.last_win = [None, None]
        self.mss, self.ws = [None, None], [None, None]
        self.sack, self.tsopt = [False, False], [False, False]
        self.ecn = False
        self.established = False
        self.pk = []
        self.sni = ""
        self.idx = idx
        self.n0 = None

    def direction(self, src, sport):
        return 0 if self.ep[0] == (src, sport) else 1

    def update(self, ts, n, d, seq, ack, flags, win, plen, wire, opts=None):
        """Feed one packet; returns a tuple of event marks (retransmission, dup-ack, ...)."""
        marks = []
        if self.n0 is None:
            self.n0 = n
        if ts is not None:
            if self.first is None:
                self.first = ts
            self.last = ts
        self.pkts[d] += 1
        self.bytes[d] += wire
        self.payload[d] += plen
        syn, ackf = flags & 0x02, flags & 0x10
        if syn and not ackf:
            if self.syn is None:
                self.syn = ts
            if flags & 0xC0:
                self.ecn = True
        elif syn and ackf:
            if self.synack is None:
                self.synack = ts
        elif (ackf and d == 0 and self.syn is not None and self.synack is not None and self.hsack is None):
            self.hsack = ts
            self.established = True
        if opts:
            self.mss[d] = opts.get("mss", self.mss[d])
            self.ws[d] = opts.get("ws", self.ws[d])
            self.sack[d] = opts.get("sack", self.sack[d])
            self.tsopt[d] = opts.get("ts", self.tsopt[d])
        if flags & 0x04:
            self.rst += 1
            self.closed, self.rst_by = "RST", d
            marks.append("rst")
        elif flags & 0x01:
            self.fin += 1
            if self.closed is None:
                self.closed = "FIN"
        if win == 0 and not (flags & 0x06):
            self.zwin += 1
            marks.append("zero-window")
        seg = plen + (1 if flags & 0x03 else 0)
        retx = False
        if seg:
            nxt = self.nxt[d]
            if nxt is not None and before(seq, nxt):
                if seq in self.seen[d]:
                    self.retrans += 1
                    retx = True
                    marks.append("retransmission")
                    if plen >= 1000:
                        self.retx_big += 1
                    self.unacked[d].pop((seq + seg) & MASK32, None)     # Karn: no RTT from retransmitted data
                else:
                    self.ooo += 1
                    marks.append("out-of-order")
            elif len(self.seen[d]) < 512:
                self.seen[d].add(seq)
            end = (seq + seg) & MASK32
            if nxt is None or not before(end, nxt):
                self.nxt[d] = end
            if plen > self.max_seg:
                self.max_seg = plen
        if ackf and plen == 0 and not (flags & 0x07):
            la = self.last_ack[d]
            other = self.nxt[1 - d]
            if la is not None and ack == la and win == self.last_win[d] and other is not None and before(ack, other):
                self.dupack += 1
                marks.append("dup-ack")
        if ackf:
            self.last_ack[d] = ack
            self.last_win[d] = win
            U = self.unacked[1 - d]
            if U and ts is not None:
                best = None
                done = []
                for end in U:
                    if not before(ack, end):                    # end <= ack: this data is acknowledged
                        done.append(end)
                        if best is None or before(best, end):
                            best = end
                if best is not None:
                    r = (ts - U[best]) * 1000.0
                    lst = self.rtts[1 - d]
                    if 0 <= r < 120000 and len(lst) < 300:
                        lst.append(r)
                for e in done:
                    del U[e]
        if seg and not retx and ts is not None:
            U = self.unacked[d]
            U[(seq + seg) & MASK32] = ts
            if len(U) > 128:
                U.pop(next(iter(U)))
        if marks and len(self.pk) < 12:
            self.pk.append(n)
        return marks

    # ---- derived values
    @property
    def duration(self):
        return (self.last - self.first) if self.first is not None and self.last is not None else 0.0

    @property
    def handshake_ms(self):
        if self.syn is not None and self.synack is not None:
            return (self.synack - self.syn) * 1000.0
        return None

    @property
    def rtt_ms(self):
        """Network RTT estimate: the larger of the two directions' median data->ACK delay
        (the direction whose ACKs come from the far side of the capture point)."""
        meds = [pctl(sorted(l), 50) for l in self.rtts if l]
        return max(meds) if meds else None

    @property
    def score(self):
        s = self.retrans * 3 + self.dupack + self.zwin * 2 + self.ooo * 0.5
        if self.rst:
            s += 2
        if self.syn is not None and self.synack is None:
            s += 3
        return s

    @property
    def blackhole(self):
        return self.retrans >= 3 and self.max_seg >= 1000 and self.retx_big >= 0.8 * self.retrans

    def end_state(self):
        if self.closed == "RST":
            return "RST by %s" % ("client" if self.rst_by == 0 else "server")
        if self.closed == "FIN":
            return "FIN"
        if self.syn is not None and self.synack is None:
            return "no SYN/ACK"
        return "open"


def parse_tcp_options(o):
    """TCP options bytes -> {'mss', 'ws', 'sack', 'ts'}."""
    res, i = {}, 0
    while i < len(o):
        k = o[i]
        if k == 0:
            break
        if k == 1:
            i += 1
            continue
        if i + 1 >= len(o) or o[i + 1] < 2:
            break
        ln = o[i + 1]
        v = o[i + 2:i + ln]
        if k == 2 and len(v) == 2:
            res["mss"] = struct.unpack("!H", v)[0]
        elif k == 3 and len(v) == 1:
            res["ws"] = v[0]
        elif k == 4:
            res["sack"] = True
        elif k == 8:
            res["ts"] = True
        i += ln
    return res


# ---- ASN.1 / X.509 (just enough to describe a server certificate)

OIDS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST"}
SIGALGS = {"1.2.840.113549.1.1.4": "md5WithRSA", "1.2.840.113549.1.1.5": "sha1WithRSA",
           "1.2.840.113549.1.1.11": "sha256WithRSA", "1.2.840.113549.1.1.12": "sha384WithRSA",
           "1.2.840.113549.1.1.13": "sha512WithRSA", "1.2.840.113549.1.1.10": "rsassa-pss",
           "1.2.840.10045.4.3.2": "ecdsa-sha256", "1.2.840.10045.4.3.3": "ecdsa-sha384",
           "1.2.840.10045.4.1": "ecdsa-sha1", "1.3.101.112": "ed25519"}
CURVES = {"1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521"}


def der_tlv(b, off):
    """-> (tag, content_start, content_end)."""
    tag = b[off]
    ln = b[off + 1]
    off += 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4:
            raise ValueError("bad DER length")
        ln = int.from_bytes(b[off:off + n], "big")
        off += n
    if off + ln > len(b):
        raise ValueError("DER overrun")
    return tag, off, off + ln


def der_oid(b):
    if not b:
        return ""
    parts = [b[0] // 40, b[0] % 40]
    v = 0
    for c in b[1:]:
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80:
            parts.append(v)
            v = 0
    return ".".join(str(x) for x in parts)


def der_children(b, s, e):
    out, p = [], s
    while p < e:
        tag, cs, ce = der_tlv(b, p)
        out.append((tag, cs, ce))
        p = ce
    return out


def der_name(b, s, e):
    """RDNSequence content -> {'CN': ..., 'O': ...}."""
    res = {}
    for _t, ss, se in der_children(b, s, e):                 # each SET
        for _t2, ps, pe in der_children(b, ss, se):          # each AttributeTypeAndValue SEQ
            kids = der_children(b, ps, pe)
            if len(kids) == 2 and kids[0][0] == 0x06:
                key = OIDS.get(der_oid(b[kids[0][1]:kids[0][2]]))
                if key and key not in res:
                    res[key] = b[kids[1][1]:kids[1][2]].decode("utf-8", "replace")
    return res


def der_time(tag, v):
    t = v.decode("ascii", "replace")
    try:
        if tag == 0x17:
            yy = int(t[0:2])
            y, rest = (2000 + yy if yy < 50 else 1900 + yy), t[2:]
        else:
            y, rest = int(t[0:4]), t[4:]
        dt = datetime(y, int(rest[0:2]), int(rest[2:4]), int(rest[4:6]), int(rest[6:8]), int(rest[8:10]), tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, IndexError):
        return None


def parse_certificate(der):
    """Minimal X.509 reader -> dict(subject, issuer, not_before, not_after, sig, key, san, self_signed, sha256)."""
    _t, s, e = der_tlv(der, 0)
    _t, ts, te = der_tlv(der, s)                              # tbsCertificate
    kids = der_children(der, ts, te)
    i = 1 if kids[0][0] == 0xA0 else 0                         # optional [0] version
    alg_k = der_children(der, kids[i + 1][1], kids[i + 1][2])[0]
    sig_oid = der_oid(der[alg_k[1]:alg_k[2]])
    issuer_k, validity_k, subject_k, spki_k = kids[i + 2], kids[i + 3], kids[i + 4], kids[i + 5]
    vk = der_children(der, validity_k[1], validity_k[2])
    nb = der_time(vk[0][0], der[vk[0][1]:vk[0][2]])
    na = der_time(vk[1][0], der[vk[1][1]:vk[1][2]])
    key = "?"
    sk = der_children(der, spki_k[1], spki_k[2])
    alg = der_children(der, sk[0][1], sk[0][2])
    alg_oid = der_oid(der[alg[0][1]:alg[0][2]])
    if alg_oid == "1.2.840.113549.1.1.1":                      # RSA: size from the modulus
        bits = der[sk[1][1] + 1:sk[1][2]]
        _t, rs, re_ = der_tlv(bits, 0)
        _t, ns, ne = der_tlv(bits, rs)
        n = bits[ns:ne].lstrip(b"\x00")
        key = "RSA %d" % (((len(n) - 1) * 8 + n[0].bit_length()) if n else 0)
    elif alg_oid == "1.2.840.10045.2.1":
        curve = der_oid(der[alg[1][1]:alg[1][2]]) if len(alg) > 1 else ""
        key = "EC " + CURVES.get(curve, curve)
    elif alg_oid == "1.3.101.112":
        key = "Ed25519"
    san = []
    for k in kids[i + 6:]:
        if k[0] == 0xA3:                                       # [3] extensions
            for _t, xs, xe in der_children(der, *der_children(der, k[1], k[2])[0][1:]):
                ek = der_children(der, xs, xe)
                if der_oid(der[ek[0][1]:ek[0][2]]) == "2.5.29.17":
                    ov = ek[-1]                                 # OCTET STRING wrapping GeneralNames
                    for gt, gs, ge in der_children(der, *der_children(der, ov[1], ov[2])[0][1:]):
                        if gt == 0x82:
                            san.append(der[gs:ge].decode("ascii", "replace"))
    return {"subject": der_name(der, subject_k[1], subject_k[2]), "issuer": der_name(der, issuer_k[1], issuer_k[2]),
            "not_before": nb, "not_after": na, "sig": SIGALGS.get(sig_oid, sig_oid), "key": key, "san": san[:30],
            "self_signed": der[issuer_k[1]:issuer_k[2]] == der[subject_k[1]:subject_k[2]],
            "sha256": hashlib.sha256(der).hexdigest()}


def host_matches(host, names):
    """TLS-style hostname match with single-label wildcards."""
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.split(".", 1)[1] == n[2:]:
            return True
    return False


# ---- link-layer discovery protocols

def parse_lldp(d):
    """LLDP TLVs -> dict(chassis, port, port_desc, name, desc, mgmt)."""
    info, i = {}, 0
    while i + 2 <= len(d):
        h = struct.unpack("!H", d[i:i + 2])[0]
        t, ln = h >> 9, h & 0x1FF
        v = d[i + 2:i + 2 + ln]
        i += 2 + ln
        if t == 0:
            break
        if t in (1, 2) and v:
            sub, val = v[0], v[1:]
            txt = mac_str(val) if sub == 4 and len(val) == 6 else printable(val, 60)
            info["chassis" if t == 1 else "port"] = txt
        elif t == 4:
            info["port_desc"] = printable(v, 60)
        elif t == 5:
            info["name"] = printable(v, 60)
        elif t == 6:
            info["desc"] = printable(v.split(b"\n")[0], 80)
        elif t == 8 and len(v) >= 6 and v[1] == 1:
            info["mgmt"] = ip4(v[2:6])
    return info


def parse_cdp(d):
    """CDP TLVs (after the 4-byte header) -> dict(name, port, platform, version, mgmt, duplex)."""
    info, i = {}, 4
    while i + 4 <= len(d):
        t, ln = struct.unpack("!HH", d[i:i + 4])
        if ln < 4:
            break
        v = d[i + 4:i + ln]
        i += ln
        if t == 1:
            info["name"] = printable(v, 60)
        elif t == 3:
            info["port"] = printable(v, 60)
        elif t == 6:
            info["platform"] = printable(v, 60)
        elif t == 5:
            info["desc"] = printable(v.split(b"\n")[0], 80)
        elif t == 0x0B and v:
            info["duplex"] = "full" if v[0] == 1 else "half"
        elif t == 2 and len(v) >= 4:
            try:                                          # first IPv4 address, NLPID encoded
                if v[4] == 1 and v[5] == 1 and v[6] == 0xCC and struct.unpack("!H", v[7:9])[0] == 4:
                    info["mgmt"] = ip4(v[9:13])
            except (IndexError, struct.error):
                pass
    return info


def parse_stp(d):
    """BPDU (after LLC) -> dict(type, root, bridge, tc) or None."""
    if len(d) < 4:
        return None
    btype = d[3]
    if btype == 0x80:
        return {"type": "TCN", "tc": True}
    if btype in (0x00, 0x02) and len(d) >= 35:
        flags = d[4]
        rp, rm = struct.unpack("!H", d[5:7])[0], mac_str(d[7:13])
        bp, bm = struct.unpack("!H", d[17:19])[0], mac_str(d[19:25])
        return {"type": "RSTP" if btype == 2 else "STP", "tc": bool(flags & 0x01),
                "root": "%d / %s" % (rp & 0xF000, rm), "bridge": "%d / %s" % (bp & 0xF000, bm),
                "root_cost": struct.unpack("!I", d[13:17])[0]}
    return None


# ---- quick header parser (filters, extraction and the flow-trace second pass)

Quick = namedtuple("Quick", "src dst proto sport dport tcp")


def quick_parse(link, data):
    """Fast L2-L4 parse -> Quick(src, dst, proto, sport, dport, tcp) or None.
    proto is 'tcp', 'udp', 'icmp', 'icmpv6', 'arp' or 'ipN'; tcp = (seq, ack, flags, win, payload_len) for TCP."""
    try:
        et, off = None, 0
        if link == 1:
            if len(data) < 14:
                return None
            et, off = struct.unpack("!H", data[12:14])[0], 14
            while et in (0x8100, 0x88A8, 0x9100) and len(data) >= off + 4:
                et = struct.unpack("!H", data[off + 2:off + 4])[0]
                off += 4
        elif link == 113:
            et, off = struct.unpack("!H", data[14:16])[0], 16
        elif link == 276:
            et, off = struct.unpack("!H", data[0:2])[0], 20
        elif link == 0:
            et, off = (0x0800 if (data[4] >> 4) == 4 else 0x86DD), 4
        elif link in (101, 228, 229):
            et, off = (0x0800 if (data[0] >> 4) == 4 else 0x86DD), 0
        if et == 0x0806 and len(data) >= off + 28:
            return Quick(ip4(data[off + 14:off + 18]), ip4(data[off + 24:off + 28]), "arp", 0, 0, None)
        if et == 0x0800:
            d = data[off:]
            ihl = (d[0] & 0x0F) * 4
            proto, src, dst = d[9], ip4(d[12:16]), ip4(d[16:20])
            totlen = struct.unpack("!H", d[2:4])[0]
            ff = struct.unpack("!H", d[6:8])[0]
            l4 = d[ihl:totlen if 20 <= totlen <= len(d) else len(d)]
            if ff & 0x1FFF:
                return Quick(src, dst, "ip%d" % proto, 0, 0, None)
        elif et == 0x86DD:
            d = data[off:]
            plen, proto = struct.unpack("!HB", d[4:7])
            src, dst = ip6(d[8:24]), ip6(d[24:40])
            p = 40
            while proto in (0, 43, 60, 44, 51) and len(d) >= p + 8:
                nxt = d[p]
                p += 8 if proto == 44 else (d[p + 1] + 1) * 8 if proto != 51 else (d[p + 1] + 2) * 4
                proto = nxt
            l4 = d[p:40 + plen if plen else len(d)]
        else:
            return None
        if proto == 6 and len(l4) >= 20:
            sp, dp, seq, ack, of, fl, win = struct.unpack("!HHIIBBH", l4[:16])
            return Quick(src, dst, "tcp", sp, dp, (seq, ack, fl, win, max(0, len(l4) - (of >> 4) * 4)))
        if proto == 17 and len(l4) >= 4:
            sp, dp = struct.unpack("!HH", l4[:4])
            return Quick(src, dst, "udp", sp, dp, None)
        return Quick(src, dst, {1: "icmp", 58: "icmpv6"}.get(proto, "ip%d" % proto), 0, 0, None)
    except (struct.error, IndexError, ValueError):
        return None


class PacketFilter:
    """--host / --port / --proto / --flow / --from / --to selection applied while reading."""

    def __init__(self, hosts=(), ports=(), protos=(), flows=(), t_from=None, t_to=None):
        self.hosts, self.ports = set(hosts), set(ports)
        self.protos = {p.lower() for p in protos}
        self.flows = list(flows)
        self.t_from, self.t_to = t_from, t_to
        self.t0 = None

    @property
    def active(self):
        return bool(self.hosts or self.ports or self.protos or self.flows or self.t_from or self.t_to)

    @property
    def l3l4(self):
        return bool(self.hosts or self.ports or self.protos or self.flows)

    @staticmethod
    def parse_time(spec, t0):
        """'+12.5' (seconds after the first packet), 'HH:MM:SS' or 'YYYY-MM-DD HH:MM:SS' (UTC) -> epoch."""
        if spec is None:
            return None
        s = spec.strip()
        if s.startswith("+"):
            return ("rel", float(s[1:]))
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%H:%M:%S"):
            try:
                dt = datetime.strptime(s, fmt)
                return ("abs", dt, fmt == "%H:%M:%S")
            except ValueError:
                continue
        raise ValueError("bad time '%s' (use +SECONDS, HH:MM:SS or 'YYYY-MM-DD HH:MM:SS' in UTC)" % spec)

    def _resolve(self, spec, ts):
        if spec is None:
            return None
        if spec[0] == "rel":
            return self.t0 + spec[1]
        dt, tonly = spec[1], spec[2]
        if tonly:
            base = datetime.fromtimestamp(self.t0, timezone.utc)
            dt = dt.replace(year=base.year, month=base.month, day=base.day)
        return dt.replace(tzinfo=timezone.utc).timestamp()

    def match(self, ts, link, data):
        if ts is not None:
            if self.t0 is None:
                self.t0 = ts
            lo, hi = self._resolve(self.t_from, ts), self._resolve(self.t_to, ts)
            if (lo is not None and ts < lo) or (hi is not None and ts > hi):
                return False
        if not self.l3l4:
            return True
        q = quick_parse(link, data)
        if q is None:
            return False
        if self.protos and q.proto not in self.protos:
            return False
        if self.hosts and q.src not in self.hosts and q.dst not in self.hosts:
            return False
        if self.ports and q.sport not in self.ports and q.dport not in self.ports:
            return False
        if self.flows:
            a, b = (q.src, q.sport), (q.dst, q.dport)
            if not any((a, b) == f or (b, a) == f for f in self.flows):
                return False
        return True

    def describe(self):
        bits = []
        if self.hosts:
            bits.append("host " + ",".join(sorted(self.hosts)))
        if self.ports:
            bits.append("port " + ",".join(str(p) for p in sorted(self.ports)))
        if self.protos:
            bits.append("proto " + ",".join(sorted(self.protos)))
        if self.flows:
            bits.append("flow " + "; ".join("%s:%d-%s:%d" % (a[0], a[1], b[0], b[1]) for a, b in self.flows))
        if self.t_from or self.t_to:
            bits.append("time window")
        return ", ".join(bits)


class PcapWriter:
    """Classic little-endian microsecond pcap writer for --extract."""

    def __init__(self, path, linktype, snaplen=262144):
        self.fh = open(path, "wb")
        self.link = linktype
        self.n = self.skipped = 0
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))

    def write(self, ts, caplen, origlen, link, data):
        if link != self.link:
            self.skipped += 1
            return
        ts = ts or 0.0
        sec = int(ts)
        self.fh.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), caplen, origlen) + data)
        self.n += 1

    def close(self):
        self.fh.close()


# ------------------------------------------------------------------ analyzer

UNREACH_CODES = {0: "net", 1: "host", 2: "protocol", 3: "port", 4: "fragmentation needed", 5: "source route failed",
                 9: "net admin prohibited", 10: "host admin prohibited", 13: "admin filtered"}


class Analyzer:
    def __init__(self):
        self.meta = {}
        self.pkts = 0
        self.bytes = 0          # on-wire bytes (origlen)
        self.cap_bytes = 0
        self.truncated = 0
        self.malformed = Counter()
        self.first_ts = self.last_ts = None
        self.sizes = []
        self.per_second = Counter()
        self.stack_pkts, self.stack_bytes = Counter(), Counter()
        # L2
        self.ethertype = Counter()
        self.mac_pkts, self.mac_bytes = Counter(), Counter()
        self.cast = Counter()
        self.vlans = Counter()
        self.arp_ops = Counter()
        self.arp_map = defaultdict(set)         # ip -> {mac}
        self.arp_gratuitous = 0
        # L3
        self.ip_ver = Counter()
        self.ip_proto = Counter()
        self.ip_tx_p, self.ip_tx_b = Counter(), Counter()
        self.ip_rx_p, self.ip_rx_b = Counter(), Counter()
        self.conv_p, self.conv_b = Counter(), Counter()
        self.ttl = Counter()
        self.dscp = Counter()
        self.frags = 0
        self.icmp = Counter()
        self.ipv6_ext = Counter()
        self.dns_names = {}                      # ip -> name learned from DNS answers
        # L4
        self.l4 = Counter()
        self.tcp_dport, self.udp_dport = Counter(), Counter()
        self.tcp_dport_b, self.udp_dport_b = Counter(), Counter()
        self.tcp_flags = Counter()
        self.flows = {}                          # key -> [pkts, bytes, proto, first_ts]
        self.tcp_flows = {}                      # key -> TcpFlow
        self.retrans = 0
        self.out_of_order = 0
        self.dupacks = 0
        self.tcp_payload_pkts = 0
        self.zero_win = 0
        self.rst = 0
        self.syn_targets = defaultdict(set)      # src -> {(dst, dport)}
        self.answered = set()                    # (client, server, sport) that replied SYN/ACK
        self.udp_port_unreach = 0
        # L5/6
        self.tls_versions, self.tls_hello_versions = Counter(), Counter()
        self.tls_sni, self.tls_alpn, self.tls_ciphers = Counter(), Counter(), Counter()
        self.tls_clienthello = self.tls_serverhello = 0
        self.tls_old = Counter()
        self.tls_records = Counter()
        # L7
        self.dns_q, self.dns_qtype, self.dns_rcode = Counter(), Counter(), Counter()
        self.dns_queries = self.dns_responses = 0
        self.dns_long = []
        self.http_methods, self.http_hosts, self.http_status = Counter(), Counter(), Counter()
        self.http_ua, self.http_server, self.http_ctype = Counter(), Counter(), Counter()
        self.http_auth = 0
        self.dhcp_types, self.dhcp_hosts, self.dhcp_vendor = Counter(), Counter(), Counter()
        self.banners = Counter()
        self.cleartext = Counter()               # protocol -> packets with credentials-like data
        self.cleartext_hosts = defaultdict(set)
        self.quic = 0
        self._pair = None
        self.ip_stacks = defaultdict(Counter)    # ip -> {leaf protocol: packets}
        self.ip_services = defaultdict(Counter)  # server ip -> {"443/tcp": connection attempts}
        self.ip_sni = defaultdict(Counter)       # server ip -> TLS server names asked for
        self.ip_http = defaultdict(Counter)      # server ip -> HTTP Host headers
        self.ip_dnsq = defaultdict(Counter)      # client ip -> DNS names it queried
        self.ssdp = Counter()
        # evidence: packet numbers per finding key, current packet context
        self.cur, self.cur_ts, self._smac = 0, None, None
        self.ev, self.evn = defaultdict(list), Counter()
        self._ports, self._fkey, self._seq, self._dkey = (0, 0), None, 0, None
        # L2 extras
        self.sec_info = {}                      # second -> [first pkt no, last pkt no, packets, Counter(protocol)]
        self.pkts_ps, self.bcast_ps, self.mcast_ps, self.arp_req_ps = Counter(), Counter(), Counter(), Counter()
        self.neighbors = {}
        self.stp_msgs, self.stp_roots, self.stp_bridges = Counter(), Counter(), set()
        self.stp_tc, self.stp_last_root, self.stp_root_changes = 0, None, 0
        self.arp_targets, self.arp_replied, self.arp_asked = defaultdict(set), set(), Counter()
        self.arp_req_pkts, self.arp_probes = defaultdict(list), 0
        self.ip_macs = defaultdict(set)
        self.dhcp_xids, self.dhcp_servers, self.dhcp_nak = {}, Counter(), 0
        # path / MTU
        self.tcp_mss = {"client (SYN)": Counter(), "server (SYN/ACK)": Counter()}
        self.tcp_ws = {"client (SYN)": Counter(), "server (SYN/ACK)": Counter()}
        self.tcp_opts = Counter()
        self.df = Counter()
        self.icmp_err, self.pmtu = Counter(), []
        # latency
        self.dns_pending, self.dns_lat = {}, []
        self.http_pending, self.http_tx = {}, []
        self.tls_ch, self.tls_lat, self.tls_split = {}, [], 0
        # TLS fingerprints / certificates, periodic connections
        self.ja3, self.ja3_info = Counter(), {}
        self.cert_buf, self.certs, self._cert_seen = {}, [], set()
        self.conn_times = defaultdict(list)
        self.ntp = 0

    # ---- top level
    def mark(self, key):
        """Remember the current packet number as evidence for a finding key."""
        self.evn[key] += 1
        lst = self.ev[key]
        if len(lst) < 40 and (not lst or lst[-1] != self.cur):
            lst.append(self.cur)

    def add(self, ts, caplen, origlen, link, data, n=None):
        self.pkts += 1
        self.cur = n if n is not None else self.pkts
        self.cur_ts = ts
        self._smac = None
        self.bytes += origlen
        self.cap_bytes += caplen
        if caplen < origlen:
            self.truncated += 1
        if ts is not None:
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts
            self.per_second[int(ts)] += origlen
            self.pkts_ps[int(ts)] += 1
        self.sizes.append(origlen)
        stack = ["link%d" % link]
        self._pair = None
        try:
            self.decode_link(link, data, origlen, stack)
        except (struct.error, IndexError, ValueError):
            self.malformed["truncated/malformed packet"] += 1
        if self._pair:
            leaf = stack[-1].upper()
            for ip in set(self._pair):
                self.ip_stacks[ip][leaf] += 1
        name = ":".join(stack)
        self.stack_pkts[name] += 1
        self.stack_bytes[name] += origlen
        if ts is not None:
            sec = int(ts)
            si = self.sec_info.get(sec)
            if si is None:
                si = self.sec_info[sec] = [self.cur, self.cur, 0, Counter()]
            si[0], si[1] = min(si[0], self.cur), max(si[1], self.cur)
            si[2] += 1
            si[3][stack[-1].upper()] += 1

    def decode_link(self, link, data, origlen, stack):
        if link == 1:
            self.decode_eth(data, origlen, stack)
        elif link == 113 and len(data) >= 16:
            proto = struct.unpack("!H", data[14:16])[0]
            stack[0] = "sll"
            self.decode_ethertype(proto, data[16:], origlen, stack)
        elif link == 276 and len(data) >= 20:
            proto = struct.unpack("!H", data[0:2])[0]
            stack[0] = "sll2"
            self.decode_ethertype(proto, data[20:], origlen, stack)
        elif link == 0 and len(data) >= 4:
            stack[0] = "null"
            self.decode_ip_any(data[4:], origlen, stack)
        elif link in (101, 228, 229):
            stack[0] = "raw"
            self.decode_ip_any(data, origlen, stack)
        else:
            stack[0] = LINKTYPES.get(link, "link%d" % link).split(" ")[0].lower()

    def decode_ip_any(self, data, origlen, stack):
        if not data:
            return
        v = data[0] >> 4
        if v == 4:
            self.decode_ipv4(data, origlen, stack)
        elif v == 6:
            self.decode_ipv6(data, origlen, stack)

    def decode_eth(self, data, origlen, stack):
        if len(data) < 14:
            self.malformed["short ethernet frame"] += 1
            return
        dst, src = data[0:6], data[6:12]
        et = struct.unpack("!H", data[12:14])[0]
        stack[0] = "eth"
        smac = mac_str(src)
        self._smac = smac
        self.mac_pkts[smac] += 1
        self.mac_bytes[smac] += origlen
        sec = int(self.cur_ts) if self.cur_ts is not None else None
        if dst == b"\xff" * 6:
            self.cast["broadcast"] += 1
            if sec is not None:
                self.bcast_ps[sec] += 1
        elif dst[0] & 1:
            self.cast["multicast"] += 1
            if sec is not None:
                self.mcast_ps[sec] += 1
        else:
            self.cast["unicast"] += 1
        off = 14
        while et in (0x8100, 0x88A8, 0x9100) and len(data) >= off + 4:
            tci, et = struct.unpack("!HH", data[off:off + 4])
            self.vlans[tci & 0x0FFF] += 1
            stack.append("vlan")
            off += 4
        if et <= 1500:                     # 802.3 length field: LLC (STP, CDP, ...)
            self.ethertype["802.3/LLC"] += 1
            self.decode_llc(src, data[off:off + et], stack)
            return
        self.decode_ethertype(et, data[off:], origlen, stack, src)

    def decode_llc(self, src, p, stack):
        if len(p) < 3:
            stack.append("llc")
        elif p[0] == 0x42 and p[1] == 0x42:
            stack.append("stp")
            b = parse_stp(p[3:])
            if b:
                self.stp_msgs[b["type"]] += 1
                if b["tc"]:
                    self.stp_tc += 1
                    self.mark("stp-tc")
                if "root" in b:
                    self.stp_roots[b["root"]] += 1
                    self.stp_bridges.add(b["bridge"])
                    if self.stp_last_root and self.stp_last_root != b["root"]:
                        self.stp_root_changes += 1
                        self.mark("stp-root")
                    self.stp_last_root = b["root"]
        elif p[0] == 0xAA and p[1] == 0xAA and len(p) >= 8 and p[3:6] == b"\x00\x00\x0c" and p[6:8] == b"\x20\x00":
            stack.append("cdp")
            self.note_neighbor("CDP", mac_str(src), parse_cdp(p[8:]))
        else:
            stack.append("llc")

    def note_neighbor(self, proto, mac, info):
        if not info:
            return
        key = (proto, mac, info.get("name") or info.get("chassis") or "")
        n = self.neighbors.get(key)
        if n is None:
            if len(self.neighbors) < 500:
                self.neighbors[key] = dict(info, proto=proto, mac=mac, count=1, pkt=self.cur)
        else:
            n["count"] += 1
    def decode_ethertype(self, et, payload, origlen, stack, src=None):
        self.ethertype[ETHERTYPES.get(et, "0x%04x" % et)] += 1
        if et == 0x0800:
            self.decode_ipv4(payload, origlen, stack)
        elif et == 0x86DD:
            self.decode_ipv6(payload, origlen, stack)
        elif et == 0x0806:
            self.decode_arp(payload, stack)
        elif et == 0x88CC:
            stack.append("lldp")
            self.note_neighbor("LLDP", mac_str(src) if src else "?", parse_lldp(payload))
        else:
            stack.append(ETHERTYPES.get(et, "0x%04x" % et).lower())
    def decode_arp(self, d, stack):
        stack.append("arp")
        if len(d) < 28:
            self.malformed["short ARP"] += 1
            return
        op = struct.unpack("!H", d[6:8])[0]
        self.arp_ops["request" if op == 1 else "reply" if op == 2 else "op%d" % op] += 1
        sha, spa, tpa = mac_str(d[8:14]), ip4(d[14:18]), ip4(d[24:28])
        if op == 1:
            if self.cur_ts is not None:
                self.arp_req_ps[int(self.cur_ts)] += 1
            if spa == "0.0.0.0":
                self.arp_probes += 1
            else:
                tg = self.arp_targets[spa]
                if len(tg) < 5000:
                    tg.add(tpa)
            self.arp_asked[tpa] += 1
            lst = self.arp_req_pkts[tpa]
            if len(lst) < 10:
                lst.append(self.cur)
        elif op == 2:
            self.arp_replied.add(spa)
        if spa != "0.0.0.0":
            self.arp_map[spa].add(sha)
            if len(self.arp_map[spa]) > 1:
                self.mark("arpconf:" + spa)
        if spa == tpa:
            self.arp_gratuitous += 1
            self.mark("arp-gratuitous")
    # ---- L3
    def count_ip(self, src, dst, length, ver, stack):
        self._pair = (src, dst)
        if self._smac is not None:
            m = self.ip_macs[src]
            if self._smac not in m and len(m) < 8:
                m.add(self._smac)
        self.ip_ver[ver] += 1
        self.ip_tx_p[src] += 1
        self.ip_tx_b[src] += length
        self.ip_rx_p[dst] += 1
        self.ip_rx_b[dst] += length
        pair = (src, dst) if src <= dst else (dst, src)
        self.conv_p[pair] += 1
        self.conv_b[pair] += length

    def decode_ipv4(self, d, origlen, stack):
        stack.append("ip")
        if len(d) < 20:
            self.malformed["short IPv4 header"] += 1
            return
        ihl = (d[0] & 0x0F) * 4
        tos, totlen, _id, ff, ttl, proto = struct.unpack("!BHHHBB", d[1:10])
        src, dst = ip4(d[12:16]), ip4(d[16:20])
        self.count_ip(src, dst, origlen, "IPv4", stack)
        self.ip_proto[IPPROTOS.get(proto, "proto %d" % proto)] += 1
        self.ttl[ttl] += 1
        self.dscp[tos >> 2] += 1
        end = totlen if 20 <= totlen <= len(d) else len(d)
        payload = d[ihl:end]
        self.df["DF set" if ff & 0x4000 else "DF clear"] += 1
        if (ff & 0x1FFF) != 0 or (ff & 0x2000):
            self.frags += 1
            self.mark("frag")
            if ff & 0x1FFF:
                stack.append("ip-frag")
                return
        self.decode_l4(proto, src, dst, payload, origlen, stack, v6=False)

    def decode_ipv6(self, d, origlen, stack):
        stack.append("ipv6")
        if len(d) < 40:
            self.malformed["short IPv6 header"] += 1
            return
        tc = ((d[0] & 0x0F) << 4) | (d[1] >> 4)
        plen, nh, hlim = struct.unpack("!HBB", d[4:8])
        src, dst = ip6(d[8:24]), ip6(d[24:40])
        self.count_ip(src, dst, origlen, "IPv6", stack)
        self.ttl[hlim] += 1
        self.dscp[tc >> 2] += 1
        off = 40
        while nh in (0, 43, 60, 44, 51) and len(d) >= off + 8:
            self.ipv6_ext[{0: "hop-by-hop", 43: "routing", 60: "dest-opts", 44: "fragment", 51: "AH"}[nh]] += 1
            if nh == 44:
                self.frags += 1
            nxt = d[off]
            off += 8 if nh == 44 else (d[off + 1] + 1) * 8 if nh != 51 else (d[off + 1] + 2) * 4
            nh = nxt
        self.ip_proto[IPPROTOS.get(nh, "proto %d" % nh)] += 1
        self.decode_l4(nh, src, dst, d[off:40 + plen if plen else len(d)], origlen, stack, v6=True)

    def decode_l4(self, proto, src, dst, p, origlen, stack, v6):
        if proto == 6:
            self.decode_tcp(src, dst, p, origlen, stack)
        elif proto == 17:
            self.decode_udp(src, dst, p, origlen, stack)
        elif proto == 1 and len(p) >= 2:
            stack.append("icmp")
            self.l4["ICMP"] += 1
            self.icmp["%s (type %d code %d)" % (ICMP_TYPES.get(p[0], "other"), p[0], p[1])] += 1
            if p[0] == 3 and p[1] == 3:
                self.udp_port_unreach += 1
                self.mark("icmp-unreach")
            if p[0] in (3, 5, 11, 12) and len(p) >= 28:
                self.note_icmp_error(src, p[0], p[1], p, False)
        elif proto == 58 and len(p) >= 2:
            stack.append("icmpv6")
            self.l4["ICMPv6"] += 1
            self.icmp["%s (type %d)" % (ICMP6_TYPES.get(p[0], "other"), p[0])] += 1
            if p[0] in (1, 2, 3, 4) and len(p) >= 48:
                self.note_icmp_error(src, p[0], p[1], p, True)
        else:
            name = IPPROTOS.get(proto, "proto %d" % proto)
            stack.append(name.lower())
            self.l4[name] += 1

    def note_icmp_error(self, reporter, t, c, p, v6):
        """ICMP error carrying the start of the offending packet: who complained about what."""
        if v6:
            inner = p[8:]
            if inner[0] >> 4 != 6:
                return
            orig_dst = ip6(inner[24:40])
            kind = ICMP6_TYPES.get(t, "error type %d" % t)
            if t == 2:
                self.pmtu.append((reporter, struct.unpack("!I", p[4:8])[0], ip6(inner[8:24]), orig_dst, self.cur))
                self.mark("pmtu")
        else:
            inner = p[8:]
            if inner[0] >> 4 != 4:
                return
            orig_dst = ip4(inner[16:20])
            kind = ICMP_TYPES.get(t, "type %d" % t)
            if t == 3:
                kind += "/" + UNREACH_CODES.get(c, "code %d" % c)
            if t == 3 and c == 4:
                self.pmtu.append((reporter, struct.unpack("!H", p[6:8])[0], ip4(inner[12:16]), orig_dst, self.cur))
                self.mark("pmtu")
        if len(self.icmp_err) < 2000:
            self.icmp_err[(reporter, kind, orig_dst)] += 1
    def flow_update(self, key, origlen, ts, proto, src_ep):
        f = self.flows.get(key)
        if f is None:
            f = self.flows[key] = [0, 0, proto, ts]
            if proto == "udp" and ts is not None:           # first packet of a UDP flow = a "connection" for periodicity
                server = key[0] if key[1] == src_ep else key[1]
                lst = self.conn_times[(src_ep[0], server[0], server[1], "udp")]
                if len(lst) < 400 and len(self.conn_times) < 100000:
                    lst.append(ts)
        f[0] += 1
        f[1] += origlen
    def decode_tcp(self, src, dst, p, origlen, stack):
        stack.append("tcp")
        self.l4["TCP"] += 1
        if len(p) < 20:
            self.malformed["short TCP header"] += 1
            return
        sport, dport, seq, ack, off_f, flags, win = struct.unpack("!HHIIBBH", p[:16])
        hl = (off_f >> 4) * 4
        syn, ackf = flags & 0x02, flags & 0x10
        opts = parse_tcp_options(p[20:hl]) if hl > 20 and syn else None
        payload = p[hl:]
        self.tcp_flags[flags_str(flags)] += 1
        a, b = (src, sport), (dst, dport)
        key = (a, b) if a <= b else (b, a)
        self.flow_update(key, origlen, self.cur_ts, "tcp", a)
        fl = self.tcp_flows.get(key)
        if fl is None:
            client, server = (b, a) if (syn and ackf) else (a, b)
            fl = self.tcp_flows[key] = TcpFlow(client, server, len(self.tcp_flows))
        d = fl.direction(src, sport)
        if syn and not ackf:
            self.syn_targets[src].add((dst, dport))
            self.mark("scan:" + src)
            self.tcp_dport[dport] += 1
            self.ip_services[dst]["%d/tcp" % dport] += 1
            self.tcp_dport_b[dport] += origlen
            if self.cur_ts is not None and len(self.conn_times) < 100000:
                lst = self.conn_times[(src, dst, dport, "tcp")]
                if len(lst) < 400:
                    lst.append(self.cur_ts)
        elif syn and ackf:
            self.answered.add((dst, src, sport))
        marks = fl.update(self.cur_ts, self.cur, d, seq, ack, flags, win, len(payload), origlen, opts)
        for m in marks:
            if m == "retransmission":
                self.retrans += 1
                self.mark("retrans")
            elif m == "out-of-order":
                self.out_of_order += 1
                self.mark("ooo")
            elif m == "dup-ack":
                self.dupacks += 1
                self.mark("dupack")
            elif m == "zero-window":
                self.zero_win += 1
                self.mark("zerowin")
            elif m == "rst":
                self.rst += 1
                self.mark("rst")
        if opts is not None:
            side = "server (SYN/ACK)" if ackf else "client (SYN)"
            if "mss" in opts:
                self.tcp_mss[side][opts["mss"]] += 1
            if "ws" in opts:
                self.tcp_ws[side][opts["ws"]] += 1
            if opts.get("sack"):
                self.tcp_opts["SACK permitted (%s)" % side] += 1
            if opts.get("ts"):
                self.tcp_opts["timestamps (%s)" % side] += 1
            if flags & 0xC0 and not ackf:
                self.tcp_opts["ECN setup (client SYN)"] += 1
        if payload:
            self.tcp_payload_pkts += 1
            self._ports, self._fkey, self._seq, self._dkey = (sport, dport), key, seq, (src, sport, dst, dport)
            if self._dkey in self.cert_buf and self.cert_feed(self._dkey, seq, payload):
                stack.append("tls")                      # continuation of the server's TLS handshake flight
                return
            self.decode_tcp_payload(src, dst, sport, dport, payload, origlen, stack)
    def decode_udp(self, src, dst, p, origlen, stack):
        stack.append("udp")
        self.l4["UDP"] += 1
        if len(p) < 8:
            self.malformed["short UDP header"] += 1
            return
        sport, dport, ulen = struct.unpack("!HHH", p[:6])
        a, b = (src, sport), (dst, dport)
        key = (a, b) if a <= b else (b, a)
        self.flow_update(key, origlen, self.cur_ts, "udp", a)
        self.udp_dport[dport] += 1
        if dport in SERVICES or dport < 1024:
            self.ip_services[dst]["%d/udp" % dport] += 1
        self.udp_dport_b[dport] += origlen
        payload = p[8:]
        if payload:
            self._ports = (sport, dport)
            self.decode_udp_payload(src, dst, sport, dport, payload, stack)
    # ---- L5-L7 over TCP
    def decode_tcp_payload(self, src, dst, sport, dport, d, origlen, stack):
        if d[0] == 0x16 and len(d) > 5 and d[1] == 3 and d[2] <= 4:
            self.decode_tls(src, dst, d, stack)
            return
        if d[0] in (0x14, 0x15, 0x17) and len(d) > 5 and d[1] == 3 and d[2] <= 4:
            stack.append("tls")
            self.tls_records[{0x14: "change-cipher-spec", 0x15: "alert", 0x17: "application-data"}[d[0]]] += 1
            return
        if d.startswith(HTTP_METHODS) or d.startswith(b"HTTP/1."):
            self.decode_http(src, dst, d, stack)
            return
        if d.startswith(b"SSH-"):
            stack.append("ssh")
            self.banners["SSH: " + printable(d.split(b"\r")[0].split(b"\n")[0], 60)] += 1
            return
        if 53 in (sport, dport) and len(d) > 14:
            self.decode_dns(src, dst, d[2:], stack)
            return
        port = dport if dport in SERVICES else sport if sport in SERVICES else None
        name = SERVICES.get(port)
        text = d[:200]
        if name == "ftp":
            stack.append("ftp")
            up = text.upper()
            if up.startswith((b"USER ", b"PASS ")):
                self.cleartext["FTP login"] += 1
                self.mark("clear:FTP login")
                self.cleartext_hosts["FTP login"].add(src if dport == 21 else dst)
            elif text[:3].isdigit():
                self.banners["FTP: " + printable(text.split(b"\r")[0], 60)] += 1
        elif name == "telnet":
            stack.append("telnet")
            self.cleartext["Telnet session"] += 1
            self.mark("clear:Telnet session")
            self.cleartext_hosts["Telnet session"].add(dst if dport == 23 else src)
        elif name in ("smtp", "submission"):
            stack.append("smtp")
            if text[:3] == b"220":
                self.banners["SMTP: " + printable(text.split(b"\r")[0], 60)] += 1
            if text.upper().startswith((b"AUTH PLAIN", b"AUTH LOGIN")):
                self.cleartext["SMTP AUTH"] += 1
                self.mark("clear:SMTP AUTH")
                self.cleartext_hosts["SMTP AUTH"].add(dst)
        elif name in ("pop3", "imap"):
            stack.append(name)
            up = text.upper()
            if b"USER " in up[:12] or b"PASS " in up[:12] or b" LOGIN " in up[:30]:
                self.cleartext[name.upper() + " login"] += 1
                self.mark("clear:" + name.upper() + " login")
                self.cleartext_hosts[name.upper() + " login"].add(dst if dport in (110, 143) else src)
        elif name == "smb":
            stack.append("smb")
        elif name:
            stack.append(name)

    def decode_tls(self, src, dst, d, stack):
        stack.append("tls")
        rec_ver = struct.unpack("!H", d[1:3])[0]
        if not (len(d) > 5 and d[5] == 1):         # a ClientHello's record version is legacy, ignore it
            self.tls_versions[TLS_VERSIONS.get(rec_ver, "0x%04x" % rec_ver)] += 1
        if len(d) < 11:
            return
        hs = d[5]
        if hs not in (1, 2):
            self.tls_records["handshake (other)"] += 1
            return
        try:
            self.parse_hello(src, dst, d, hs)
        except (IndexError, struct.error):
            self.tls_split += 1                    # hello spans several segments; not reassembled

    def parse_hello(self, src, dst, d, hs):
        body = d[9:]
        ver = ch_ver = struct.unpack("!H", body[0:2])[0]
        off = 34                                   # version + random
        off += 1 + body[off]                       # session id
        sni = None
        ciphers, ext_types, curves, pformats = [], [], [], []
        if hs == 1:
            cs = struct.unpack("!H", body[off:off + 2])[0]
            ciphers = [struct.unpack("!H", body[off + 2 + i:off + 4 + i])[0] for i in range(0, cs - 1, 2)]
            off += 2 + cs
            off += 1 + body[off]                   # compression methods
        else:
            sel = struct.unpack("!H", body[off:off + 2])[0]
            off += 3                               # cipher + compression
        if off + 2 <= len(body):
            elen = struct.unpack("!H", body[off:off + 2])[0]
            off += 2
            end = min(len(body), off + elen)
            while off + 4 <= end:
                et, el = struct.unpack("!HH", body[off:off + 4])
                ed = body[off + 4:off + 4 + el]
                off += 4 + el
                ext_types.append(et)
                if et == 0 and hs == 1 and len(ed) >= 5:
                    sni = ed[5:5 + struct.unpack("!H", ed[3:5])[0]].decode("latin-1")
                elif et == 0x10 and hs == 1 and len(ed) >= 3:
                    i = 2
                    while i < len(ed):
                        n = ed[i]
                        self.tls_alpn[ed[i + 1:i + 1 + n].decode("latin-1")] += 1
                        i += 1 + n
                elif et == 0x0A and hs == 1 and len(ed) >= 2:
                    curves = [struct.unpack("!H", ed[i:i + 2])[0] for i in range(2, len(ed) - 1, 2)]
                elif et == 0x0B and hs == 1 and ed:
                    pformats = list(ed[1:])
                elif et == 0x2B:
                    if hs == 1 and ed:
                        vers = [struct.unpack("!H", ed[i:i + 2])[0] for i in range(1, len(ed) - 1, 2)]
                        vers = [v for v in vers if v in TLS_VERSIONS]
                        if vers:
                            ver = max(vers)
                    elif hs == 2 and len(ed) >= 2:
                        ver = struct.unpack("!H", ed[:2])[0]
        label = TLS_VERSIONS.get(ver, "0x%04x" % ver)
        if hs == 1:
            self.tls_clienthello += 1
            g = lambda xs: [str(x) for x in xs if x not in GREASE]
            ja3s = "%d,%s,%s,%s,%s" % (ch_ver, "-".join(g(ciphers)), "-".join(g(ext_types)), "-".join(g(curves)),
                                       "-".join(str(x) for x in pformats))
            try:
                h = hashlib.md5(ja3s.encode(), usedforsecurity=False).hexdigest()
            except TypeError:
                h = hashlib.md5(ja3s.encode()).hexdigest()
            self.ja3[h] += 1
            info = self.ja3_info.setdefault(h, {"string": ja3s, "sni": Counter(), "clients": set(), "pkt": self.cur})
            if sni:
                info["sni"][sni] += 1
            if len(info["clients"]) < 50:
                info["clients"].add(src)
            if self.cur_ts is not None and len(self.tls_ch) < 100000:
                self.tls_ch[self._fkey] = (self.cur_ts, sni, self.cur)
            fl = self.tcp_flows.get(self._fkey)
            if fl is not None and sni:
                fl.sni = sni
        else:
            self.tls_serverhello += 1
            self.tls_ciphers["0x%04x" % sel] += 1
            ch = self.tls_ch.pop(self._fkey, None)
            if ch is not None and self.cur_ts is not None and len(self.tls_lat) < 200000:
                self.tls_lat.append(((self.cur_ts - ch[0]) * 1000.0, ch[1] or "", src, label, ch[2], self.cur))
            if ver != 0x0304 and self._dkey not in self.cert_buf and len(self.cert_buf) < 20000:
                self.cert_buf[self._dkey] = {"base": self._seq, "segs": {0: d}, "bytes": len(d), "done": False}
                self.cert_try(self._dkey)
        self.tls_hello_versions[("ClientHello offers up to " if hs == 1 else "ServerHello selects ") + label] += 1
        if label in ("SSLv3", "TLS 1.0", "TLS 1.1"):
            self.tls_old[("client offers at most " if hs == 1 else "server selected ") + label] += 1
            self.mark("tls-old")
        if sni:
            self.tls_sni[sni] += 1
            self.ip_sni[dst][sni] += 1

    def cert_feed(self, dkey, seq, payload):
        """Collect the server's TLS flight (TLS <= 1.2) across segments. True while the data is consumed."""
        cb = self.cert_buf[dkey]
        if cb["done"]:
            return False
        off = (seq - cb["base"]) & MASK32
        if off >= 65536 or cb["bytes"] + len(payload) > 40000:
            cb["done"] = True
            return False
        if off not in cb["segs"]:
            cb["segs"][off] = payload
            cb["bytes"] += len(payload)
            self.cert_try(dkey)
        return True

    def cert_try(self, dkey):
        cb = self.cert_buf[dkey]
        buf = b""
        for off in sorted(cb["segs"]):                 # contiguous prefix only
            seg = cb["segs"][off]
            if off > len(buf):
                break
            buf += seg[len(buf) - off:]
        pos, hs = 0, b""
        while pos + 5 <= len(buf):
            if buf[pos] != 0x16:                       # ChangeCipherSpec / data: handshake flight is over
                cb["done"] = True
                return
            rlen = struct.unpack("!H", buf[pos + 3:pos + 5])[0]
            if pos + 5 + rlen > len(buf):
                break
            hs += buf[pos + 5:pos + 5 + rlen]
            pos += 5 + rlen
        p = 0
        while p + 4 <= len(hs):
            mtype, mlen = hs[p], int.from_bytes(hs[p + 1:p + 4], "big")
            if p + 4 + mlen > len(hs):
                return                                  # message not complete yet
            if mtype == 11 and mlen >= 6:
                cb["done"] = True
                chain = hs[p + 4 + 3:p + 4 + mlen]
                if len(chain) >= 3:
                    clen = int.from_bytes(chain[0:3], "big")
                    der = chain[3:3 + clen]
                    try:
                        info = parse_certificate(der)
                    except (ValueError, IndexError, struct.error):
                        return
                    if info["sha256"] not in self._cert_seen:
                        self._cert_seen.add(info["sha256"])
                        fl = self.tcp_flows.get(self._fkey)
                        info.update(server=(dkey[0], dkey[1]), sni=fl.sni if fl else "", pkt=self.cur, servers=1)
                        self.certs.append(info)
                    else:
                        fl = self.tcp_flows.get(self._fkey)
                        for c in self.certs:
                            if c["sha256"] == info["sha256"]:
                                c["servers"] += 1
                                if not c["sni"] and fl is not None and fl.sni:
                                    c["sni"] = fl.sni
                return
            if mtype == 14:                              # ServerHelloDone without a Certificate (resumed session)
                cb["done"] = True
                return
            p += 4 + mlen
    def decode_http(self, src, dst, d, stack):
        stack.append("http")
        head = d.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
        first = head[0]
        hdrs = {}
        for line in head[1:]:
            k, _, v = line.partition(b":")
            hdrs[k.strip().lower()] = v.strip()
        if first.startswith(b"HTTP/"):
            parts = first.split(b" ", 2)
            code = parts[1].decode() if len(parts) >= 2 and parts[1].isdigit() else ""
            if code:
                self.http_status[code] += 1
            if b"server" in hdrs:
                self.http_server[printable(hdrs[b"server"], 60)] += 1
            if b"content-type" in hdrs:
                self.http_ctype[printable(hdrs[b"content-type"].split(b";")[0], 40)] += 1
            q = self.http_pending.get(self._fkey)
            if q and self.cur_ts is not None and len(self.http_tx) < 200000:
                t0, host, path, pk = q.popleft()
                self.http_tx.append(((self.cur_ts - t0) * 1000.0, host, path, code, src, pk, self.cur))
        else:
            parts = first.split(b" ")
            self.http_methods[parts[0].decode("latin-1")] += 1
            host = printable(hdrs.get(b"host", b""), 60)
            if b"host" in hdrs:
                self.http_hosts[host] += 1
                self.ip_http[dst][host] += 1
            if self.cur_ts is not None and len(self.http_pending) < 100000:
                q = self.http_pending.setdefault(self._fkey, deque())
                if len(q) < 16:
                    q.append((self.cur_ts, host or dst, printable(parts[1], 80) if len(parts) > 1 else "", self.cur))
            if b"user-agent" in hdrs:
                self.http_ua[printable(hdrs[b"user-agent"], 70)] += 1
            if b"authorization" in hdrs:
                self.http_auth += 1
                if hdrs[b"authorization"].lower().startswith(b"basic"):
                    self.cleartext["HTTP Basic auth"] += 1
                    self.cleartext_hosts["HTTP Basic auth"].add(dst)
                    self.mark("clear:HTTP Basic auth")
            if first.startswith(b"POST ") and (b"password" in d.lower() or b"passwd" in d.lower()):
                self.cleartext["HTTP POST with password field"] += 1
                self.cleartext_hosts["HTTP POST with password field"].add(dst)
                self.mark("clear:HTTP POST with password field")
    # ---- L5-L7 over UDP
    def decode_udp_payload(self, src, dst, sport, dport, d, stack):
        ports = (sport, dport)
        if 53 in ports or 5353 in ports or 5355 in ports:
            self.decode_dns(src, dst, d, stack, mdns=(5353 in ports))
        elif 67 in ports or 68 in ports:
            self.decode_dhcp(src, d, stack)
        elif 123 in ports and len(d) >= 48:
            stack.append("ntp")
            self.ntp += 1
        elif 1900 in ports:
            stack.append("ssdp")
            first = d.split(b"\r\n")[0]
            self.ssdp[printable(first, 40)] += 1
        elif 443 in ports and len(d) > 5 and d[0] & 0x80 and struct.unpack("!I", d[1:5])[0] in (1, 0x6b3343cf, 0xff00001d, 0):
            stack.append("quic")
            self.quic += 1
        elif 161 in ports or 162 in ports:
            stack.append("snmp")
        elif 514 in ports:
            stack.append("syslog")
        elif 51820 in ports:
            stack.append("wireguard")
        elif 137 in ports:
            stack.append("nbns")
        elif 138 in ports:
            stack.append("nbdgm")
        elif 5060 in ports:
            stack.append("sip")
        else:
            svc = SERVICES.get(dport) or SERVICES.get(sport)
            if svc:
                stack.append(svc)

    def decode_dns(self, src, dst, d, stack, mdns=False):
        stack.append("mdns" if mdns else "dns")
        if len(d) < 12:
            self.malformed["short DNS"] += 1
            return
        tid, fl, qd, an = struct.unpack("!HHHH", d[:8])
        qr = fl >> 15
        rcode = fl & 0xF
        off = 12
        qname, qtype = None, None
        for _ in range(min(qd, 1)):
            qname, off = read_dns_name(d, off)
            if off + 4 > len(d):
                return
            qtype = struct.unpack("!H", d[off:off + 2])[0]
            off += 4
            if qname is not None:
                if not qr:
                    self.dns_q[qname.lower()] += 1
                    self.ip_dnsq[src][qname.lower()] += 1
                    self.dns_qtype[DNS_TYPES.get(qtype, str(qtype))] += 1
                    if len(qname) > 60 or max((len(x) for x in qname.split(".")), default=0) > 40:
                        self.dns_long.append(qname)
                        self.mark("dns-long")
        sp, dp = self._ports
        if qr:
            self.dns_responses += 1
            self.dns_rcode[DNS_RCODES.get(rcode, "rcode %d" % rcode)] += 1
            if rcode == 3:
                self.mark("nxdomain")
            pend = self.dns_pending.pop((dst, src, dp, sp, tid), None) if not mdns else None
            if pend is not None and self.cur_ts is not None and len(self.dns_lat) < 200000:
                self.dns_lat.append(((self.cur_ts - pend[0]) * 1000.0, pend[1] or "", src,
                                     DNS_RCODES.get(rcode, "rcode %d" % rcode), pend[3], self.cur))
            for _ in range(min(an, 20)):           # learn IP -> name from answers
                name, off = read_dns_name(d, off)
                if off + 10 > len(d):
                    break
                rtype, _cls, _ttl, rdl = struct.unpack("!HHIH", d[off:off + 10])
                off += 10
                rd = d[off:off + rdl]
                off += rdl
                if rtype == 1 and rdl == 4 and name:
                    self.dns_names.setdefault(ip4(rd), name.lower())
                elif rtype == 28 and rdl == 16 and name:
                    self.dns_names.setdefault(ip6(rd), name.lower())
        else:
            self.dns_queries += 1
            if not mdns and self.cur_ts is not None and len(self.dns_pending) < 200000:
                self.dns_pending.setdefault((src, dst, sp, dp, tid), (self.cur_ts, qname, qtype, self.cur, dst))
    def decode_dhcp(self, src, d, stack):
        stack.append("dhcp")
        if len(d) < 240 or d[236:240] != b"\x63\x82\x53\x63":
            return
        xid = struct.unpack("!I", d[4:8])[0]
        mac = mac_str(d[28:34])
        msg, server_id = None, None
        off = 240
        while off + 2 <= len(d):
            code = d[off]
            if code == 255:
                break
            if code == 0:
                off += 1
                continue
            ln = d[off + 1]
            val = d[off + 2:off + 2 + ln]
            if code == 53 and val:
                msg = val[0]
                self.dhcp_types[DHCP_TYPES.get(val[0], str(val[0]))] += 1
            elif code == 54 and len(val) == 4:
                server_id = ip4(val)
            elif code == 12:
                self.dhcp_hosts[printable(val, 40)] += 1
            elif code == 60:
                self.dhcp_vendor[printable(val, 40)] += 1
            off += 2 + ln
        if msg is None:
            return
        x = self.dhcp_xids.get(xid)
        if x is None and len(self.dhcp_xids) < 50000:
            x = self.dhcp_xids[xid] = {"mac": mac, "types": set(), "pkt": self.cur}
        if x is not None:
            x["types"].add(msg)
        if msg in (2, 5):                                    # OFFER / ACK come from a server
            self.dhcp_servers[server_id or src] += 1
        if msg == 6:
            self.dhcp_nak += 1
            self.mark("dhcp-nak")


# ------------------------------------------------------------------ whois

def public_ips(ips):
    out = []
    for ip in ips:
        try:
            if ipaddress.ip_address(ip).is_global:
                out.append(ip)
        except ValueError:
            pass
    return out


def cymru_whois(ips, chunk=400):
    """Bulk whois via Team Cymru -> {ip: {"asn", "cc", "org"}}. Raises OSError if unreachable."""
    res = {}
    for i in range(0, len(ips), chunk):
        q = "begin\nverbose\n" + "\n".join(ips[i:i + chunk]) + "\nend\n"
        data = b""
        with socket.create_connection(("whois.cymru.com", 43), timeout=8) as s:
            s.settimeout(20)
            s.sendall(q.encode())
            while True:
                part = s.recv(8192)
                if not part:
                    break
                data += part
        for line in data.decode(errors="replace").splitlines():
            p = [x.strip() for x in line.split("|")]
            if len(p) >= 7 and p[0].isdigit():       # AS | IP | prefix | CC | registry | allocated | AS name
                res[p[1]] = {"asn": "AS" + p[0], "cc": p[3], "org": re.sub(r",\s*[A-Z]{2}$", "", p[6])}
    return res


# ------------------------------------------------------------------ report model

SEVERITY = {"high": ("HIGH", "bgred", 0), "medium": ("MEDIUM", "bgyellow", 1), "info": ("INFO", "bgblue", 2)}


def evidence_text(fd):
    if not fd.pkts:
        return ""
    more = fd.total - len(fd.pkts)
    return "packets " + ", ".join(str(p) for p in fd.pkts) + (" (+%d more)" % more if more > 0 else "")


class Style:
    """ANSI styling; every call is a no-op when colors are off."""
    CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34",
             "magenta": "35", "cyan": "36", "bgred": "41;1;97", "bgyellow": "43;1;30", "bgblue": "44;1;97"}

    def __init__(self, on):
        self.on = on

    def __call__(self, names, text):
        if not self.on or not text:
            return text
        codes = ";".join(self.CODES[n] for n in names.split("+"))
        return "\033[%sm%s\033[0m" % (codes, text)


def block_bar(frac, width):
    frac = max(0.0, min(1.0, frac))
    cells = frac * width
    full = int(cells)
    s = "█" * full
    if full < width:
        s += " ▏▎▍▌▋▊▉"[int((cells - full) * 8)]
    if frac > 0 and not s.strip():
        s = "▏"
    return s.ljust(width)


def tall_chart(values, height=4):
    """Block-character area chart; returns `height` rows, top first."""
    mx = max(values) or 1
    levels = [v / mx * height * 8 for v in values]
    rows = []
    for r in range(height - 1, -1, -1):
        line = ""
        for lv in levels:
            x = lv - r * 8
            line += " " if x <= 0 else "█" if x >= 8 else SPARKS[max(0, int(math.ceil(x)) - 1)]
        rows.append(line)
    return rows


def bin_series(per_second, n):
    """Rebin {epoch_second: bytes} into n bins -> (bins, start, end, seconds_per_bin)."""
    lo, hi = min(per_second), max(per_second)
    span = hi - lo + 1
    n = max(1, min(n, span))                      # data has 1 s resolution: never make bins shorter than a second
    bins = [0] * n
    for sec, b in per_second.items():
        bins[min(n - 1, int((sec - lo) * n / span))] += b
    return bins, lo, hi + 1, span / n


_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4, "ms": 1, "s": 1000}


def sort_key(cell):
    """Numeric value of a table cell ('1,234', '12.5%', '1.4 MB') or None."""
    m = re.fullmatch(r"(-?\d+(?:\.\d+)?)\s*(%|[KMGT]?B|ms|s)?", cell.replace(",", "").strip())
    if not m:
        return None
    return float(m.group(1)) * _UNITS.get(m.group(2), 1)


def bar_col(headers):
    return next((i for i, h in enumerate(headers) if h.startswith("%")), None)


def pct_value(cell):
    c = cell.strip()
    try:
        return float(c[:-1]) / 100.0 if c.endswith("%") else None
    except ValueError:
        return None


def _numlike(s):
    s = s.replace(",", "").replace("%", "").replace(".", "", 1).strip()
    return s.isdigit() or s in ("-", "")


class Report:
    """Sections of typed items, built once and rendered as text, JSON or HTML."""

    def __init__(self):
        self.sections = []
        self.meta = {}

    def section(self, title):
        s = {"title": title, "items": []}
        self.sections.append(s)
        return s

    @staticmethod
    def kv(sec, key, value):
        sec["items"].append({"t": "kv", "k": key, "v": str(value)})

    @staticmethod
    def note(sec, text, text_only=False):
        sec["items"].append({"t": "note", "text": text, "text_only": text_only})

    @staticmethod
    def table(sec, title, headers, rows):
        if rows:
            sec["items"].append({"t": "table", "title": title, "headers": headers,
                                 "rows": [[str(c) for c in r] for r in rows]})

    @staticmethod
    def kpis(sec, items):
        sec["items"].append({"t": "kpis", "items": items})

    @staticmethod
    def findings(sec, items):
        sec["items"].append({"t": "findings", "items": sorted(items, key=lambda x: SEVERITY[x.sev][2])})

    @staticmethod
    def timeline(sec, per_second, info=None):
        if per_second:
            sec["items"].append({"t": "timeline", "per_second": per_second, "info": info or {}})

    @staticmethod
    def donut(sec, title, pairs):
        if pairs:
            sec["items"].append({"t": "donut", "title": title, "pairs": pairs})

    @staticmethod
    def flowtraces(sec, traces):
        if traces:
            sec["items"].append({"t": "flowtraces", "traces": traces})

    @staticmethod
    def hosts(sec, hosts):
        if hosts:
            sec["items"].append({"t": "hosts", "hosts": hosts})

    @staticmethod
    def graph(sec, nodes, edges, hubs):
        if len(nodes) >= 2:
            sec["items"].append({"t": "graph", "nodes": nodes, "edges": edges, "hubs": hubs})

    # ------------------------------------------------------------ text
    def to_text(self, st, width=100):
        out = []
        for s in self.sections:
            title = s["title"]
            out += ["", st("bold+cyan", "━━ ") + st("bold", title) + " " + st("cyan", "━" * max(3, width - len(title) - 5))]
            kw = max((len(i["k"]) for i in s["items"] if i["t"] == "kv"), default=0)
            prev = None
            for it in s["items"]:
                t = it["t"]
                if t == "kv" and prev in ("note", "findings", "kpis"):
                    out.append("")
                prev = t
                if t == "kv":
                    out.append("  %s  %s" % (st("dim", it["k"].ljust(kw)), it["v"]))
                elif t == "note":
                    out.append("  " + st("dim", it["text"]))
                elif t == "table":
                    out += self._table_text(st, it, width)
                elif t == "kpis":
                    out += self._kpis_text(st, it["items"], width)
                elif t == "findings":
                    out += self._findings_text(st, it["items"], width)
                elif t == "timeline":
                    out += self._timeline_text(st, it["per_second"], width)
                elif t == "graph":
                    out += self._graph_text(st, it, width)
                elif t == "hosts":
                    out += self._hosts_text(st, it["hosts"], width)
                elif t == "flowtraces":
                    for tr in it["traces"][:3]:
                        out += self._trace_text(st, tr, width)
        return "\n".join(out).lstrip("\n") + "\n"

    @staticmethod
    def _table_text(st, it, width):
        headers, rows = it["headers"], it["rows"]
        bi = bar_col(headers)
        cols = list(zip(*([headers] + rows)))
        widths = [min(max(len(c) for c in col), 58) for col in cols]
        budget = width - 6 - (14 if bi is not None else 0) - 2 * (len(widths) - 1)
        right = [all(_numlike(r[i]) for r in rows) for i in range(len(headers))]
        fixed = [right[i] or all(re.fullmatch(r"\[?[0-9a-fA-F:.]+\]?(:\d+)?", r[i]) for r in rows) for i in range(len(headers))]
        for floor, only_flex in ((12, True), (16, False)):
            while sum(widths) > budget:
                cand = [i for i in range(len(widths)) if widths[i] > floor and (not only_flex or not fixed[i])]
                if not cand:
                    break
                i = max(cand, key=lambda k: widths[k])
                widths[i] -= 1

        def cell(i, c):
            if len(c) > widths[i]:
                c = c[:widths[i] - 1] + "…"
            return c.rjust(widths[i]) if right[i] else c.ljust(widths[i])
        out = ["", "  " + st("bold", it["title"])]
        out.append("    " + "  ".join(st("dim", cell(i, h)) for i, h in enumerate(headers)) + (" " * 14 if bi is not None else ""))
        out.append("    " + st("dim", "  ".join("─" * w for w in widths)) + (st("dim", "  " + "─" * 12) if bi is not None else ""))
        for r in rows:
            line = "    " + "  ".join(cell(i, c) for i, c in enumerate(r))
            if bi is not None:
                f = pct_value(r[bi])
                line += "  " + st("cyan", block_bar(f if f is not None else 0, 12))
            out.append(line.rstrip() if bi is None else line)
        return out

    @staticmethod
    def _kpis_text(st, items, width):
        cw = max(14, max(max(len(i[0]), len(i[1]), len(i[2])) for i in items) + 2)
        per = max(1, (width - 2) // (cw + 2))
        out = [""]
        for start in range(0, len(items), per):
            chunk = items[start:start + per]
            out.append("  " + " ".join("┌" + "─" * cw + "┐" for _ in chunk))
            out.append("  " + " ".join("│" + st("dim", (" " + c[0]).ljust(cw)) + "│" for c in chunk))
            out.append("  " + " ".join("│" + st("bold+cyan", (" " + c[1]).ljust(cw)) + "│" for c in chunk))
            out.append("  " + " ".join("│" + st("dim", (" " + c[2]).ljust(cw)) + "│" for c in chunk))
            out.append("  " + " ".join("└" + "─" * cw + "┘" for _ in chunk))
        return out

    @staticmethod
    def _findings_text(st, items, width):
        out = [""]
        if not items:
            return out + ["  " + st("green", "✔ ") + "Nothing notable found by the built-in checks."]
        for fd in items:
            label, style, _ = SEVERITY[fd.sev]
            lines = textwrap.wrap(fd.text, max(30, width - 14)) or [""]
            out.append("  " + st(style, " %-6s " % label) + " " + lines[0])
            out += ["  " + " " * 9 + " " + l for l in lines[1:]]
            ev = evidence_text(fd)
            if ev:
                out.append("  " + " " * 9 + " " + st("dim", "↳ " + ev))
            if fd.filt:
                for i, l in enumerate(textwrap.wrap(fd.filt, max(30, width - 24)) or [""]):
                    out.append("  " + " " * 9 + " " + st("dim", "↳ filter: " if i == 0 else "          ") + st("cyan", l))
        return out

    @staticmethod
    def _timeline_text(st, per_second, width):
        n = max(20, min(80, width - 20))
        bins, lo, hi, bs = bin_series(per_second, n)
        n = len(bins)
        k = max(1, min(6, 48 // n))                   # few bins (short capture): stretch columns so the chart stays readable
        rows = ["".join(ch * k for ch in row) for row in tall_chart(bins, 4)]
        n *= k
        peak = human_bps(max(bins) * 8 / bs)
        out = ["", "  " + st("bold", "Traffic over time") + st("dim", "  (bandwidth per %.2f s)" % bs)]
        for i, r in enumerate(rows):
            lab = peak if i == 0 else "0" if i == len(rows) - 1 else ""
            out.append("    " + st("dim", lab.rjust(10)) + st("dim", " ┤") + st("cyan", r))
        out.append("    " + " " * 10 + st("dim", " └" + "─" * n))
        a, b = fmt_ts(lo)[11:19], fmt_ts(hi)[11:19]
        out.append("    " + " " * 12 + st("dim", a + " " * max(1, n - len(a) - len(b)) + b + " UTC"))
        return out

    @staticmethod
    def _trace_text(st, tr, width):
        aw = max(34, min(58, width - 44))
        out = ["", "  " + st("bold", tr["title"]), "    " + st("dim", tr["stats_line"]),
               "    " + st("dim", "filter: ") + st("cyan", tr["filter"]), ""]
        out.append("    " + st("dim", "%5s  %10s  %s" % ("PKT", "TIME", "client ".ljust(aw // 2) + " server".rjust(aw - aw // 2))))
        for e in tr["ladder"]:
            label = " " + e["label"] + " "
            if e["d"] == 0:
                arrow = "├" + label.ljust(aw - 2, "─")[:aw - 2] + "▶"
            else:
                arrow = "◀" + label.rjust(aw - 2, "─")[-(aw - 2):] + "┤"
            col = {"r": "red", "o": "yellow", "p": "magenta"}.get(e["cls"])
            note = ("  " + e["mark"]) if e["mark"] else ""
            out.append("    %5d  %10s  %s%s" % (e["n"], e["t"], st(col, arrow) if col else arrow, st(col, note) if col else note))
        if tr["omitted"]:
            out.append("    " + st("dim", "(%d packets not shown)" % tr["omitted"]))
        return out

    @staticmethod
    def _hosts_text(st, hosts, width):
        rows = [[h["ip"], h["cls"], h["org"] or "-", "{:,}".format(h["tx_pkts"] + h["rx_pkts"]),
                 human_bytes(h["tx_bytes"] + h["rx_bytes"]), ", ".join(s for s, _ in h["services"][:3]) or "-"] for h in hosts]
        return Report._table_text(st, {"title": "Host profiles (open the HTML report for full per-host cards)",
                                       "headers": ["IP", "Class", "Network", "Packets", "Bytes", "Services"], "rows": rows}, width)

    @staticmethod
    def _graph_text(st, it, width):
        out = ["", "  " + st("bold", "Talker map") + st("dim", "  (busiest hosts and their biggest peers)")]
        bw = 14
        for hub in it["hubs"]:
            out.append("")
            out.append("  " + st("bold+magenta", hub["label"]) + st("dim", "  %s, %s" % (hub["cls"], human_bytes(hub["bytes"]))))
            mx = max((p[1] for p in hub["peers"]), default=1) or 1
            for i, (label, b, pk) in enumerate(hub["peers"]):
                branch = "└─" if i == len(hub["peers"]) - 1 else "├─"
                lab = label if len(label) <= 44 else label[:43] + "…"
                out.append("   %s %s %s %s %s" % (st("dim", branch), lab.ljust(44), st("cyan", block_bar(b / mx, bw)),
                                                  human_bytes(b).rjust(9), st("dim", "{:,} pkts".format(pk))))
        return out

    # ------------------------------------------------------------ json
    def to_json(self):
        data = {}
        for s in self.sections:
            sec = {"values": {}, "notes": [], "tables": {}}
            for it in s["items"]:
                t = it["t"]
                if t == "kv":
                    sec["values"][it["k"]] = it["v"]
                elif t == "note":
                    sec["notes"].append(it["text"])
                elif t == "table":
                    sec["tables"][it["title"]] = [dict(zip(it["headers"], r)) for r in it["rows"]]
                elif t == "kpis":
                    sec["kpis"] = {k: v for k, v, _ in it["items"]}
                elif t == "findings":
                    sec["findings"] = [{"severity": x.sev, "text": x.text, "wireshark_filter": x.filt,
                                        "packets": x.pkts, "packet_count": x.total} for x in it["items"]]
                elif t == "timeline":
                    bins, lo, hi, bs = bin_series(it["per_second"], 60)
                    sec["timeline"] = {"start": lo, "end": hi, "seconds_per_bin": bs, "bytes": bins}
                elif t == "hosts":
                    sec["hosts"] = it["hosts"]
                elif t == "flowtraces":
                    sec["flows"] = [{k: v for k, v in tr.items() if k in ("title", "client", "server", "filter", "extract", "stats", "ladder")}
                                    for tr in it["traces"]]
                elif t == "graph":
                    sec["graph"] = {"nodes": it["nodes"], "edges": [
                        {"a": a, "b": b, "bytes": by, "packets": pk} for a, b, by, pk in it["edges"]]}
            data[s["title"]] = sec
        return data

    # ------------------------------------------------------------ html
    def to_html(self):
        return render_html(self)


# ------------------------------------------------------------------ html renderer

HTML_CSS = """
:root{--bg:#f4f6f9;--card:#fff;--ink:#141a22;--mute:#5a6675;--line:#e2e7ee;--bar:#93c5fd;--head:#0f172a;
--c1:#2563eb;--c2:#ea580c;--c3:#16a34a;--c4:#9333ea;--c5:#0891b2;--c6:#db2777;--c7:#ca8a04;--c8:#64748b;
--high:#dc2626;--med:#d97706;--info:#2563eb;--ok:#16a34a}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0d1117;--card:#161b22;--ink:#e6edf3;
--mute:#9aa7b4;--line:#2a313c;--bar:#1f6feb;--head:#010409;--c1:#58a6ff;--c2:#ff9b4a;--c3:#56d364;--c4:#c297ff;
--c5:#39c5cf;--c6:#ff7eb6;--c7:#e3b341;--c8:#8b949e;--high:#ff6b6b;--med:#f0a53a;--info:#58a6ff;--ok:#56d364}}
:root[data-theme="dark"]{--bg:#0d1117;--card:#161b22;--ink:#e6edf3;--mute:#9aa7b4;--line:#2a313c;--bar:#1f6feb;
--head:#010409;--c1:#58a6ff;--c2:#ff9b4a;--c3:#56d364;--c4:#c297ff;--c5:#39c5cf;--c6:#ff7eb6;--c7:#e3b341;
--c8:#8b949e;--high:#ff6b6b;--med:#f0a53a;--info:#58a6ff;--ok:#56d364}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:min(94vw,1560px);margin:0 auto;padding:0 16px}
header.top{background:var(--head);color:#fff;padding:22px 0}
header.top h1{margin:0 0 4px;font-size:22px;font-weight:650;letter-spacing:.2px}
header.top .sub{color:#aab6c5;font-size:13px;word-break:break-all}
.theme{float:right;background:transparent;color:#fff;border:1px solid #475569;border-radius:6px;padding:4px 10px;cursor:pointer}
nav{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line)}
nav .wrap{display:flex;gap:4px;overflow-x:auto;padding-top:6px;padding-bottom:6px}
nav a{color:var(--mute);text-decoration:none;white-space:nowrap;padding:4px 10px;border-radius:6px;font-size:13px}
nav a:hover{background:var(--bg);color:var(--ink)}
main{padding:20px 0 48px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.kpi{display:block;color:inherit;text-decoration:none;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;transition:border-color .15s,box-shadow .15s}
a.kpi:hover{border-color:var(--c1);box-shadow:0 1px 8px rgba(37,99,235,.18)}
a.lg{color:inherit;text-decoration:none;border-bottom:1px dotted var(--mute)}a.lg:hover{color:var(--c1);border-bottom-style:solid}
.donut a circle:hover{opacity:.75}
.chart.tl .hit{cursor:pointer;outline:none}.chart.tl .hit:hover,.chart.tl .hit:focus{fill:var(--c1);fill-opacity:.12}.chart.tl .hit.sel{fill:var(--c2);fill-opacity:.22}
.tpanel{margin-top:8px;border:1px solid var(--line);border-radius:8px;padding:8px 12px;font-size:13px;min-height:40px}
.tpanel .hint{color:var(--mute)}.tpanel dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 14px;margin:0}.tpanel dt{color:var(--mute)}.tpanel dd{margin:0;word-break:break-word}
.tpanel code{background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:1px 5px;word-break:break-all}
.kpi .l{font-size:12px;color:var(--mute);text-transform:uppercase;letter-spacing:.5px}
.kpi .v{font-size:24px;font-weight:650;font-variant-numeric:tabular-nums;margin:2px 0}
.kpi .s{font-size:12px;color:var(--mute)}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:18px}
section h2{margin:0 0 12px;font-size:16px;letter-spacing:.3px;display:flex;justify-content:space-between;align-items:baseline;gap:12px}
a.sectop{font-size:12px;font-weight:400;color:var(--mute);text-decoration:none;white-space:nowrap}a.sectop:hover{color:var(--ink)}
h3{margin:0 0 8px;font-size:13px;color:var(--mute);font-weight:600}
dl.kv{display:grid;grid-template-columns:minmax(200px,max-content) 1fr;gap:4px 18px;margin:0 0 12px}
dl.kv dt{color:var(--mute)}dl.kv dd{margin:0;font-variant-numeric:tabular-nums;word-break:break-word}
p.note{color:var(--mute);margin:6px 0;font-size:13px}
.tables{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,560px),1fr));gap:14px;margin-top:6px}
.tcard{border:1px solid var(--line);border-radius:10px;padding:10px 12px;min-width:0}
.tcard.wide{grid-column:1/-1}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:4px 8px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
tr:last-child td{border-bottom:0}
th{color:var(--mute);font-weight:600;cursor:pointer;user-select:none}
th:hover{color:var(--ink)}th.asc::after{content:" \\25B2"}th.desc::after{content:" \\25BC"}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.txt{white-space:normal}
.bar{position:relative;min-width:80px;height:18px;line-height:18px}
.bar i{position:absolute;left:0;top:2px;bottom:2px;background:var(--bar);opacity:.6;border-radius:3px}
.bar span{position:relative;display:block;text-align:right;padding-right:4px}
.findings{display:flex;flex-direction:column;gap:8px}
.finding{display:flex;gap:10px;align-items:flex-start}
.badge{flex:none;min-width:70px;text-align:center;font-size:11px;font-weight:700;letter-spacing:.6px;color:#fff;border-radius:5px;padding:2px 8px}
.badge.high{background:var(--high)}.badge.medium{background:var(--med)}.badge.info{background:var(--info)}
.ok{color:var(--ok);font-weight:600}
.chart{width:100%;height:auto;display:block}
.chart text{fill:var(--mute);font-size:11px}
.chart .lbl{fill:var(--ink);stroke:var(--card);stroke-width:3px;paint-order:stroke}
section>h3{margin-top:14px}
.fbody{flex:1;min-width:0}.evid{font-size:12px;color:var(--mute);margin-top:2px;display:flex;flex-wrap:wrap;gap:4px 10px;align-items:center}
.evid code{background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:1px 5px;color:var(--ink);word-break:break-all}
button.copy{font-size:11px;border:1px solid var(--line);background:var(--card);color:var(--mute);border-radius:4px;padding:0 6px;cursor:pointer}
button.copy:hover{color:var(--ink)}
.trace{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-bottom:14px}
.trace h3{color:var(--ink);font-size:14px;margin:0 0 4px}.trace .meta{font-size:12px;color:var(--mute);margin-bottom:6px}
.trace .meta code{background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:1px 5px;color:var(--ink);word-break:break-all}
.pair{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));gap:12px;margin-top:8px}
.chart .a-r{stroke:var(--high);fill:var(--high)}.chart .a-o{stroke:var(--med);fill:var(--med)}.chart .a-p{stroke:var(--c4);fill:var(--c4)}.chart .a-n{stroke:var(--c8);fill:var(--c8)}
.chart .a-c{stroke:var(--c1);fill:var(--c1)}.chart .a-s{stroke:var(--c2);fill:var(--c2)}
.chart .small{font-size:10px}
section,.host{scroll-margin-top:56px}
a.ip{color:var(--c1);text-decoration:none;border-bottom:1px dotted var(--c1)}a.ip:hover{border-bottom-style:solid}
.hostlist{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,520px),1fr));gap:14px}
.host{border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.host:target{outline:2px solid var(--c1);outline-offset:2px;background:color-mix(in srgb,var(--c1) 6%,var(--card))}
.hhead{display:flex;justify-content:space-between;align-items:baseline}.hhead h3{font-size:15px;color:var(--ink);margin:0 0 6px}
a.back{font-size:12px;color:var(--mute);text-decoration:none}a.back:hover{color:var(--ink)}
.minis{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px;margin-top:8px}
.mini{min-width:0}.mini table{table-layout:auto}.mini td,.mini td.txt{padding:2px 6px;white-space:normal;word-break:break-word;max-width:none}.mini h3{margin:0 0 2px}
.donuts{display:flex;flex-wrap:wrap;gap:24px;margin-bottom:10px}
.donut{display:flex;gap:16px;align-items:center}
.donut svg{width:150px;height:150px;flex:none}
.donut .c{font-size:15px;font-weight:650;fill:var(--ink);text-anchor:middle}
.donut .c2{font-size:10px;fill:var(--mute);text-anchor:middle}
.legend{list-style:none;margin:0;padding:0;font-size:12px}
.legend li{display:flex;gap:6px;align-items:center;white-space:nowrap}
.legend b{width:10px;height:10px;border-radius:2px;display:inline-block}
.legend em{font-style:normal;color:var(--mute);margin-left:6px}
.graphlegend{display:flex;gap:16px;font-size:12px;color:var(--mute);margin:4px 0 0}
.graphlegend b{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px}
@media print{a.sectop{display:none}}
a.totop{position:fixed;right:22px;bottom:22px;z-index:20;background:var(--c1);color:#fff;text-decoration:none;font-size:13px;font-weight:600;
padding:9px 14px;border-radius:999px;box-shadow:0 2px 10px rgba(0,0,0,.28);opacity:0;visibility:hidden;transform:translateY(8px);transition:opacity .2s,transform .2s,visibility .2s}
a.totop.show{opacity:1;visibility:visible;transform:none}a.totop:hover{filter:brightness(1.1)}
@media print{a.totop{display:none}nav,.theme{display:none}body{background:#fff}section{break-inside:avoid}}
"""

HTML_JS = """
(function(){var r=document.documentElement,b=document.querySelector('.theme');
if(b)b.onclick=function(){var d=r.getAttribute('data-theme')==='dark'||(!r.getAttribute('data-theme')&&matchMedia('(prefers-color-scheme: dark)').matches);r.setAttribute('data-theme',d?'light':'dark')};
(function(){var P=document.getElementById('tpanel');if(!P)return;
function show(h){document.querySelectorAll('.hit.sel').forEach(function(x){x.classList.remove('sel')});h.classList.add('sel');
var d=h.dataset,rows=[['Window',d.win],['Packets','#'+d.pk.replace('-',' \u2013 #')+'  ('+Number(d.n).toLocaleString()+' packets)'],['Rate',d.rate],['Protocols',d.mix]];
P.textContent='';var dl=document.createElement('dl');rows.forEach(function(r){var a=document.createElement('dt'),b=document.createElement('dd');a.textContent=r[0];b.textContent=r[1];dl.appendChild(a);dl.appendChild(b)});
[['Wireshark filter',d.flt],['Extract','' + d.cmd]].forEach(function(r){var a=document.createElement('dt'),b=document.createElement('dd'),c=document.createElement('code'),k=document.createElement('button');a.textContent=r[0];c.textContent=r[1];
k.type='button';k.className='copy';k.dataset.t=r[1];k.textContent='copy';b.appendChild(c);b.appendChild(document.createTextNode(' '));b.appendChild(k);dl.appendChild(a);dl.appendChild(b)});
P.appendChild(dl)}
document.querySelectorAll('.hit').forEach(function(h){h.addEventListener('click',function(){show(h)});h.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();show(h)}})})})();
document.addEventListener('click',function(e){var b=e.target.closest('.copy');if(!b)return;var t=b.dataset.t;
try{navigator.clipboard.writeText(t)}catch(x){var r=document.createRange();r.selectNodeContents(b.previousElementSibling);getSelection().removeAllRanges();getSelection().addRange(r)}
b.textContent='copied';setTimeout(function(){b.textContent='copy'},1200)});
var tt=document.querySelector('.totop');if(tt){var secs=[].slice.call(document.querySelectorAll('main > section')),cur=null;
var chk=function(){var y=window.pageYOffset||document.documentElement.scrollTop;cur=null;
for(var i=0;i<secs.length;i++){if(secs[i].getBoundingClientRect().top<=70)cur=secs[i];else break}
var atTop=!cur||Math.abs(cur.getBoundingClientRect().top-56)<24;
tt.classList.toggle('show',y>400);tt.innerHTML=atTop?'&#8593; Page top':'&#8593; Section top'};
addEventListener('scroll',chk,{passive:true});chk();
tt.addEventListener('click',function(e){chk();if(cur&&!(Math.abs(cur.getBoundingClientRect().top-56)<24)){e.preventDefault();cur.scrollIntoView({block:'start'})}})}
document.querySelectorAll('table.sortable th').forEach(function(th,i){th.onclick=function(){
var t=th.closest('table'),tb=t.tBodies[0],dir=th.classList.contains('asc')?-1:1;
t.querySelectorAll('th').forEach(function(x){x.classList.remove('asc','desc')});th.classList.add(dir===1?'asc':'desc');
var rows=[].slice.call(tb.rows);rows.sort(function(a,c){var x=a.cells[i],y=c.cells[i],p=x.dataset.v,q=y.dataset.v;
if(p!==undefined&&q!==undefined)return(parseFloat(p)-parseFloat(q))*dir;return x.textContent.localeCompare(y.textContent)*dir});
rows.forEach(function(x){tb.appendChild(x)})}})})();
"""


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def _nav_label(title):
    m = re.match(r"LAYER (\S+) - ([^(]+)", title)
    if m:
        return "L%s %s" % (m.group(1), m.group(2).strip().title())
    return re.sub(r"\b(Mtu|Tcp|Udp|Ip|Tls|Dns|Http)\b", lambda m: m.group(1).upper(), title.title())


def _e(x):
    return html.escape(str(x), quote=True)


LINKABLE = set()                      # IPs that have a host card; set by render_html
IP_RE = re.compile(r"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)(?![\w.:])")


def host_id(ip):
    return "host-" + re.sub(r"[^a-z0-9]+", "-", ip.lower()).strip("-")


def linkify(text):
    """Escape text; IPs that have a host card become links to it."""
    out, last = [], 0
    for m in IP_RE.finditer(text):
        ip = m.group(1)
        if ip in LINKABLE:
            out.append(_e(text[last:m.start()]))
            out.append('<a class="ip" href="#%s">%s</a>' % (host_id(ip), _e(ip)))
            last = m.end()
    out.append(_e(text[last:]))
    return "".join(out)


CELL_RE = re.compile(r"^(?:\[([0-9a-fA-F:.]+)\](?::\d+)?|(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?|([0-9a-fA-F]*:[0-9a-fA-F:.]*))(?=\s|$)")


def linkify_cell(text):
    """Table cells: 'ip', 'ip  (name)', 'ip:port' or '[v6]:port' - link the address part only."""
    m = CELL_RE.match(text)
    if m:
        g = next(i for i in (1, 2, 3) if m.group(i))
        ip = m.group(g)
        if ip in LINKABLE:
            s, e = m.span(g)
            return _e(text[:s]) + '<a class="ip" href="#%s">%s</a>' % (host_id(ip), _e(ip)) + _e(text[e:])
    return _e(text)


def _html_table(it):
    headers, rows = it["headers"], it["rows"]
    bi = bar_col(headers)
    num = [all(_numlike(r[i]) for r in rows) for i in range(len(headers))]
    out = ['<div class="tcard%s"><h3>%s</h3><table class="sortable"><thead><tr>' % (" wide" if len(headers) >= 4 else "", _e(it["title"]))]
    for i, h in enumerate(headers):
        out.append('<th class="%s">%s</th>' % ("num" if num[i] else "", _e(h)))
    out.append("</tr></thead><tbody>")
    for r in rows:
        out.append("<tr>")
        for i, c in enumerate(r):
            key = sort_key(c)
            dv = ' data-v="%s"' % key if key is not None else ""
            if i == bi and pct_value(c) is not None:
                out.append('<td class="num"%s><div class="bar"><i style="width:%.1f%%"></i><span>%s</span></div></td>'
                           % (dv, min(100.0, pct_value(c) * 100), _e(c)))
            else:
                out.append('<td class="%s"%s title="%s">%s</td>' % ("num" if num[i] else "txt", dv, _e(c),
                                                                    linkify(c) if headers[i] == "IP addresses" else linkify_cell(c)))
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def _svg_timeline(per_second, info=None, t0=None, path=""):
    n = 120
    bins, lo, hi, bs = bin_series(per_second, n)
    n = len(bins)
    rates = [b * 8 / bs for b in bins]
    mx = max(rates) or 1
    # aggregate the per-second packet ranges / protocol mixes into the chart's bins
    win = {}
    for sec, (first, last, cnt, protos) in (info or {}).items():
        j = min(n - 1, int((sec - lo) * n / (hi - lo)))
        w = win.setdefault(j, [first, last, 0, Counter()])
        w[0], w[1], w[2] = min(w[0], first), max(w[1], last), w[2] + cnt
        w[3].update(protos)
    W, H, L, B, T, Rr = 900, 210, 70, 28, 10, 10
    pw, ph = W - L - Rr, H - T - B
    bw = pw / n
    out = ['<svg class="chart tl" viewBox="0 0 %d %d" role="img" aria-label="Traffic over time (click a bar for details)">' % (W, H)]
    for k in range(5):
        y = T + ph - ph * k / 4
        out.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="var(--line)"/>' % (L, W - Rr, y, y))
        out.append('<text x="%d" y="%.1f" text-anchor="end">%s</text>' % (L - 6, y + 4, _e(human_bps(mx * k / 4) if k else "0")))
    for i, r in enumerate(rates):
        if r <= 0:
            continue
        h = max(1.0, ph * r / mx)
        ws, we = lo + i * bs, lo + (i + 1) * bs
        out.append('<rect class="tbar" x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="var(--c1)" rx="1"/>'
                   % (L + i * bw, T + ph - h, max(1.0, bw - 1), h))
        w = win.get(i)
        if w:
            rel0, rel1 = max(0.0, ws - (t0 if t0 is not None else lo)), max(0.0, we - (t0 if t0 is not None else lo))
            mix = ", ".join("%s %.0f%%" % (k, 100.0 * v / w[2]) for k, v in w[3].most_common(4))
            sub = ".%03d" % int((ws % 1) * 1000) if bs < 1 else ""
            subx = ".%03d" % int((we % 1) * 1000) if bs < 1 else ""
            cmd = "pcap_analyzer.py %s --from +%.3f --to +%.3f --extract window.pcap" % (shlex.quote(path), rel0, rel1)
            out.append('<rect class="hit" x="%.2f" y="%d" width="%.2f" height="%d" fill="transparent" tabindex="0" role="button" '
                       'data-win="%s" data-pk="%d-%d" data-n="%d" data-rate="%s" data-mix="%s" data-flt="frame.number >= %d && frame.number <= %d" '
                       'data-cmd="%s"><title>%s UTC - %s (click for details)</title></rect>'
                       % (L + i * bw, T, bw, ph, _e("%s%s \u2192 %s%s UTC" % (fmt_ts(ws)[11:19], sub, fmt_ts(we)[11:19], subx)),
                          w[0], w[1], w[2], _e(human_bps(r)), _e(mix), w[0], w[1], _e(cmd), _e(fmt_ts(ws)[11:19]), _e(human_bps(r))))
    for frac, anchor in ((0, "start"), (0.5, "middle"), (1, "end")):
        x = L + pw * frac
        out.append('<text x="%.1f" y="%d" text-anchor="%s">%s</text>' % (x, H - 8, anchor, _e(fmt_ts(lo + (hi - lo) * frac)[11:19] + " UTC")))
    out.append("</svg>")
    out.append('<div class="tpanel" id="tpanel" aria-live="polite"><span class="hint">Click a bar to see that time window: '
               'packet range, protocol mix, a Wireshark filter and an extract command.</span></div>')
    return "".join(out)


def _svg_donut(title, pairs, href_for=None):
    total = sum(v for _, v in pairs) or 1
    top7 = pairs[:7]
    rest = sum(v for _, v in pairs[7:])
    if rest:
        top7 = top7 + [("other", rest)]
    r, sw = 56, 24
    circ = 2 * math.pi * r
    segs, legend, cum = [], [], 0.0
    for i, (lab, v) in enumerate(top7):
        ln = circ * v / total
        col = "var(--c%d)" % (i % 8 + 1)
        href = href_for(lab) if href_for else None
        circle = ('<circle r="%d" cx="75" cy="75" fill="none" stroke="%s" stroke-width="%d" stroke-dasharray="%.2f %.2f" '
                  'stroke-dashoffset="%.2f" transform="rotate(-90 75 75)"%s><title>%s: %s (%.1f%%)%s</title></circle>'
                  % (r, col, sw, max(0.0, ln - 1.0), circ - max(0.0, ln - 1.0), -cum, ' style="cursor:pointer"' if href else "",
                     _e(lab), "{:,}".format(v), 100.0 * v / total, " - click to open the related section" if href else ""))
        segs.append('<a href="%s">%s</a>' % (href, circle) if href else circle)
        name = '<a class="lg" href="%s">%s</a>' % (href, _e(lab)) if href else _e(lab)
        legend.append('<li><b style="background:%s"></b>%s<em>%.1f%%</em></li>' % (col, name, 100.0 * v / total))
        cum += ln
    return ('<div class="donut"><svg viewBox="0 0 150 150" role="img" aria-label="%s">%s<text class="c" x="75" y="76">%s</text>'
            '<text class="c2" x="75" y="90">packets</text></svg><div><h3>%s</h3><ul class="legend">%s</ul></div></div>'
            % (_e(title), "".join(segs), _e("{:,}".format(total)), _e(title), "".join(legend)))


def _graph_layout(nodes, edges, W, H):
    n = len(nodes)
    rnd = random.Random(7)
    idx = {nd["ip"]: i for i, nd in enumerate(nodes)}
    pos = [[W / 2 + (rnd.random() - 0.5) * W * 0.6, H / 2 + (rnd.random() - 0.5) * H * 0.6] for _ in nodes]
    k = math.sqrt(W * H / max(n, 1)) * 0.75
    temp = W / 6
    mxb = max((e[2] for e in edges), default=1) or 1
    for _ in range(250):
        disp = [[0.0, 0.0] for _ in nodes]
        for i in range(n):
            for j in range(i + 1, n):
                dx, dy = pos[i][0] - pos[j][0], pos[i][1] - pos[j][1]
                d = max(0.5, math.hypot(dx, dy))
                f = k * k / d
                disp[i][0] += dx / d * f
                disp[i][1] += dy / d * f
                disp[j][0] -= dx / d * f
                disp[j][1] -= dy / d * f
        for a, b, by, _pk in edges:
            i, j = idx[a], idx[b]
            dx, dy = pos[i][0] - pos[j][0], pos[i][1] - pos[j][1]
            d = max(0.5, math.hypot(dx, dy))
            f = d * d / k * (0.4 + 0.6 * by / mxb)
            disp[i][0] -= dx / d * f
            disp[i][1] -= dy / d * f
            disp[j][0] += dx / d * f
            disp[j][1] += dy / d * f
        for i in range(n):
            dx, dy = disp[i][0] + (W / 2 - pos[i][0]) * 0.02, disp[i][1] + (H / 2 - pos[i][1]) * 0.02
            d = max(0.01, math.hypot(dx, dy))
            pos[i][0] = min(W - 60, max(60, pos[i][0] + dx / d * min(d, temp)))
            pos[i][1] = min(H - 30, max(30, pos[i][1] + dy / d * min(d, temp)))
        temp *= 0.975
    return pos


def _svg_graph(it):
    nodes, edges = it["nodes"], it["edges"]
    W, H = 900, 520
    pos = _graph_layout(nodes, edges, W, H)
    idx = {nd["ip"]: i for i, nd in enumerate(nodes)}
    mxn = max(nd["bytes"] for nd in nodes) or 1
    mxe = max((e[2] for e in edges), default=1) or 1
    color = {"private": "var(--c1)", "public": "var(--c2)"}
    out = ['<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="Conversation map">' % (W, H)]
    for a, b, by, pk in edges:
        i, j = idx[a], idx[b]
        out.append('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="var(--c8)" stroke-opacity=".45" stroke-width="%.2f">'
                   '<title>%s - %s: %s, %s packets</title></line>'
                   % (pos[i][0], pos[i][1], pos[j][0], pos[j][1], 1 + 7 * math.sqrt(by / mxe),
                      _e(a), _e(b), _e(human_bytes(by)), "{:,}".format(pk)))
    for nd, (x, y) in zip(nodes, pos):
        link = nd["ip"] in LINKABLE
        if link:
            out.append('<a href="#%s" style="cursor:pointer">' % host_id(nd["ip"]))
        rad = 6 + 20 * math.sqrt(nd["bytes"] / mxn)
        col = color.get(nd["cls"], "var(--c8)")
        out.append('<circle cx="%.1f" cy="%.1f" r="%.1f" fill="%s" fill-opacity=".85" stroke="var(--card)" stroke-width="2">'
                   '<title>%s (%s)%s - %s, %s packets</title></circle>'
                   % (x, y, rad, col, _e(nd["label"]), _e(nd["cls"]), _e(" - " + nd["org"] if nd.get("org") else ""),
                      _e(human_bytes(nd["bytes"])), "{:,}".format(nd["pkts"])))
        lab = nd["label"] if len(nd["label"]) <= 28 else nd["label"][:27] + "…"
        out.append('<text class="lbl" x="%.1f" y="%.1f" text-anchor="middle">%s</text>' % (x, y + rad + 12, _e(lab)))
        if link:
            out.append("</a>")
    out.append("</svg>")
    out.append('<div class="graphlegend"><span><b style="background:var(--c1)"></b>private</span>'
               '<span><b style="background:var(--c2)"></b>public</span><span><b style="background:var(--c8)"></b>other</span>'
               '<span>node size = traffic, link width = bytes exchanged</span></div>')
    return "".join(out)


def _svg_ladder(tr):
    ev = tr["ladder"]
    W, left, right, top, rh = 880, 215, 665, 52, 25
    H = top + len(ev) * rh + 14
    out = ['<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="Packet ladder diagram">' % (W, H)]
    out.append('<defs>' + "".join(
        '<marker id="ah%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0,1 L10,5 L0,9 z" class="a-%s"/></marker>' % (c, c) for c in "ropnc") + '</defs>')
    out.append('<text class="lbl" x="%d" y="16" text-anchor="middle">%s</text>' % (left, _e(tr["client"])))
    out.append('<text x="%d" y="30" text-anchor="middle" class="small">client</text>' % left)
    out.append('<text class="lbl" x="%d" y="16" text-anchor="middle">%s</text>' % (right, _e(tr["server"])))
    out.append('<text x="%d" y="30" text-anchor="middle" class="small">server</text>' % right)
    for x in (left, right):
        out.append('<line x1="%d" x2="%d" y1="36" y2="%d" stroke="var(--c8)" stroke-width="2"/>' % (x, x, H - 6))
    for i, e in enumerate(ev):
        y = top + i * rh
        x1, x2 = (left, right) if e["d"] == 0 else (right, left)
        cls = e["cls"] or ("c" if e["d"] == 0 else "n")
        out.append('<line x1="%d" y1="%d" x2="%d" y2="%d" class="a-%s" stroke-width="1.6" marker-end="url(#ah%s)"/>'
                   % (x1, y, x2, y + 9, cls, cls))
        out.append('<text x="%d" y="%d" text-anchor="middle" class="small lbl">%s</text>' % ((left + right) / 2, y - 3, _e(e["label"])))
        out.append('<text x="6" y="%d" class="small">#%d  %s</text>' % (y + 4, e["n"], _e(e["t"])))
        if e["mark"]:
            out.append('<text x="%d" y="%d" text-anchor="end" class="small a-%s" stroke="none">%s</text>' % (W - 6, y + 4, cls, _e(e["mark"])))
    out.append("</svg>")
    return "".join(out)


def _svg_tput(tr):
    (b0, b1), t0, bs = tr["tput"]
    W, H, L, B, T, R = 440, 190, 52, 24, 8, 8
    n = len(b0)
    mx = max(max(b0), max(b1), 1) * 8 / bs
    pw, ph = W - L - R, H - T - B
    bw = pw / n
    out = ['<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="Throughput over time">' % (W, H)]
    for k in range(3):
        y = T + ph - ph * k / 2
        out.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="var(--line)"/>' % (L, W - R, y, y))
        out.append('<text x="%d" y="%.1f" text-anchor="end" class="small">%s</text>' % (L - 4, y + 3, _e(human_bps(mx * k / 2) if k else "0")))
    for series, cls, off in ((b0, "a-c", 0), (b1, "a-s", bw / 2)):
        for i, v in enumerate(series):
            if v:
                h = max(1.0, ph * (v * 8 / bs) / mx)
                out.append('<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" class="%s" stroke="none" opacity=".85"><title>%s</title></rect>'
                           % (L + i * bw + off, T + ph - h, max(1.0, bw / 2 - 0.5), h, cls, _e(human_bps(v * 8 / bs))))
    out.append('<text x="%d" y="%d" class="small">0 s</text><text x="%d" y="%d" text-anchor="end" class="small">%.2f s</text>'
               % (L, H - 6, W - R, H - 6, bs * n))
    out.append('<text x="%d" y="14" class="small a-c" stroke="none">client&#8594;server</text>'
               '<text x="%d" y="14" class="small a-s" stroke="none">server&#8594;client</text>' % (L + 8, L + 110))
    out.append("</svg>")
    return "".join(out)


def _svg_seq(tr):
    pts = tr["pts"]
    W, H, L, B, T, R = 440, 190, 52, 24, 8, 8
    if not pts:
        return ""
    tmax = max(p[0] for p in pts) or 1e-6
    smax = max(p[2] for p in pts) or 1
    pw, ph = W - L - R, H - T - B
    out = ['<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="TCP sequence graph">' % (W, H)]
    out.append('<line x1="%d" x2="%d" y1="%d" y2="%d" stroke="var(--line)"/><line x1="%d" x2="%d" y1="%d" y2="%d" stroke="var(--line)"/>'
               % (L, W - R, T + ph, T + ph, L, L, T, T + ph))
    for p in pts[:2500]:
        x, y = L + pw * p[0] / tmax, T + ph - ph * p[2] / smax
        if p[3]:
            out.append('<circle cx="%.1f" cy="%.1f" r="3.2" class="a-r" stroke="none"><title>retransmission</title></circle>' % (x, y))
        else:
            out.append('<circle cx="%.1f" cy="%.1f" r="1.6" class="a-%s" stroke="none"/>' % (x, y, "c" if p[1] == 0 else "s"))
    out.append('<text x="%d" y="%d" class="small">0 s</text><text x="%d" y="%d" text-anchor="end" class="small">%.2f s</text>'
               % (L, H - 6, W - R, H - 6, tmax))
    out.append('<text x="%d" y="14" class="small">sequence (bytes sent, per direction) over time</text>' % (L + 4))
    out.append('<text x="%d" y="%d" text-anchor="end" class="small">%s</text>' % (L - 4, T + 8, _e(human_bytes(smax))))
    out.append("</svg>")
    return "".join(out)


def _html_trace(tr):
    return ('<div class="trace"><h3>%s</h3><div class="meta">%s<br>filter <code>%s</code> <button type="button" class="copy" data-t="%s">copy</button>'
            ' &middot; extract: <code>%s</code></div>%s<div class="pair">%s%s</div></div>'
            % (linkify(tr["title"]), _e(tr["stats_line"]), _e(tr["filter"]), _e(tr["filter"]), _e(tr["extract"]),
               _svg_ladder(tr) + ('<p class="note">%d more packets not shown.</p>' % tr["omitted"] if tr["omitted"] else ""),
               _svg_tput(tr), _svg_seq(tr)))


def _html_finding(fd):
    ev = ""
    if fd.pkts or fd.filt:
        bits = []
        if fd.pkts:
            bits.append('<span>%s</span>' % _e(evidence_text(fd)))
        if fd.filt:
            bits.append('<span>filter <code>%s</code> <button type="button" class="copy" data-t="%s">copy</button></span>'
                        % (_e(fd.filt), _e(fd.filt)))
        ev = '<div class="evid">%s</div>' % " &middot; ".join(bits)
    return ('<div class="finding"><span class="badge %s">%s</span><div class="fbody"><div>%s</div>%s</div></div>'
            % (fd.sev, SEVERITY[fd.sev][0], linkify(fd.text), ev))


def _host_card(h):
    def mini(title, pairs, linkify_first=False):
        if not pairs:
            return ""
        rows = "".join("<tr><td class=\"txt\">%s</td><td class=\"num\">%s</td></tr>" % (
            linkify_cell(k) if linkify_first else _e(k), _e(v)) for k, v in pairs)
        return '<div class="mini"><h3>%s</h3><table>%s</table></div>' % (_e(title), rows)
    kv = [("Class", h["cls"]), ("Network", h["org"] or "-"), ("Sent", "%s pkts, %s" % ("{:,}".format(h["tx_pkts"]), human_bytes(h["tx_bytes"]))),
          ("Received", "%s pkts, %s" % ("{:,}".format(h["rx_pkts"]), human_bytes(h["rx_bytes"])))]
    if h["name"]:
        kv.insert(1, ("Name (from DNS)", h["name"]))
    dl = "".join("<dt>%s</dt><dd>%s</dd>" % (_e(k), _e(v)) for k, v in kv)
    finds = "".join(_html_finding(fd) for fd in h["findings"])
    body = "".join([
        mini("Top peers (by bytes)", [("%s" % p, "%s, %s pkts" % (human_bytes(b), "{:,}".format(pk))) for p, b, pk in h["peers"]], True),
        mini("Protocols", [(k, "{:,}".format(v)) for k, v in h["protocols"]]),
        mini("Services contacted on this host", [(k + ("  " + SERVICES.get(int(k.split("/")[0]), "")), "{:,}".format(v)) for k, v in h["services"]]),
        mini("TLS server names requested", [(k, "{:,}".format(v)) for k, v in h["sni"]]),
        mini("HTTP hosts requested", [(k, "{:,}".format(v)) for k, v in h["http"]]),
        mini("DNS names queried by this host", [(k, "{:,}".format(v)) for k, v in h["dns"]]),
    ])
    return ('<div class="host" id="%s"><div class="hhead"><h3>%s</h3><a class="back" href="#hosts">&uarr; all hosts</a></div>'
            '<dl class="kv">%s</dl>%s<div class="minis">%s</div></div>' % (host_id(h["ip"]), _e(h["ip"]), dl,
                                                                         ('<div class="findings">%s</div>' % finds) if finds else "", body))


def render_html(rep):
    global LINKABLE
    LINKABLE = set(rep.meta.get("linkable", ()))
    meta = rep.meta
    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">'
             '<meta name="viewport" content="width=device-width,initial-scale=1">'
             '<title>PCAP report - %s</title><style>%s</style></head><body>' % (_e(os.path.basename(meta.get("path", ""))), HTML_CSS)]
    parts.append('<header class="top" id="top"><div class="wrap"><button class="theme" type="button">Theme</button>'
                 '<h1>Packet capture report</h1><div class="sub">%s &middot; %s &middot; generated %s</div></div></header>'
                 % (_e(meta.get("path", "")), _e(meta.get("format", "")), _e(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))))
    def sec_id(prefix):
        return next((_slug(s["title"]) for s in rep.sections if s["title"].startswith(prefix)), None)
    ids = {k: sec_id(v) for k, v in (("hier", "PROTOCOL HIERARCHY"), ("l1", "LAYER 1"), ("l2", "LAYER 2"), ("l3", "LAYER 3"),
                                     ("l4", "LAYER 4"), ("tls", "LAYER 5-6"), ("l7", "LAYER 7"), ("hosts", "HOSTS"))}
    proto_sec = {}
    for names, key in ((("ARP", "LLC", "STP", "LLDP", "CDP", "VLAN", "SLL", "SLL2", "NULL", "RAW", "ETH"), "l2"),
                       (("IP", "IPV6", "ICMP", "ICMPV6", "IGMP", "GRE", "ESP", "AH", "IP-FRAG"), "l3"),
                       (("TCP", "UDP", "SCTP"), "l4"), (("TLS", "HTTPS", "QUIC", "WIREGUARD"), "tls"),
                       (("DNS", "MDNS", "HTTP", "DHCP", "NTP", "SSH", "FTP", "SMTP", "SSDP", "SNMP", "SYSLOG", "POP3", "IMAP",
                         "TELNET", "SIP", "NBNS", "NBDGM", "SMB", "HTTP-ALT", "DOMAIN"), "l7")):
        for n in names:
            proto_sec[n] = key

    def href_for(label):
        key = proto_sec.get(label.upper(), "hier")
        return "#" + ids[key] if ids.get(key) else None
    kpi_target = {"PACKETS": "hier", "DATA": "l1", "DURATION": "l1", "HOSTS": "hosts", "FLOWS": "l4"}
    nav = [("findings", "Findings")] + [(_slug(s["title"]), _nav_label(s["title"])) for s in rep.sections
                                          if not all(it["t"] in ("kpis", "findings") for it in s["items"])]
    parts.append('<nav><div class="wrap">%s</div></nav>' % "".join(
        '<a href="#%s">%s</a>' % (h, _e(l)) for h, l in nav))
    parts.append('<main class="wrap">')
    for s in rep.sections:
        for it in s["items"]:
            if it["t"] == "kpis":
                parts.append('<div class="kpis">%s</div>' % "".join(
                    '<a class="kpi" href="#%s"><div class="l">%s</div><div class="v">%s</div><div class="s">%s</div></a>'
                    % (ids.get(kpi_target.get(l)) or "findings" if l != "FINDINGS" else "findings", _e(l), _e(v), _e(sub))
                    for l, v, sub in it["items"]))
            elif it["t"] == "findings":
                body = ('<div class="finding"><span class="ok">&#10004;</span><span>Nothing notable found by the built-in checks.</span></div>'
                        if not it["items"] else "".join(_html_finding(x) for x in it["items"]))
                parts.append('<section id="findings"><h2 style="display:block">Findings <span class="note" style="font-weight:400;color:var(--mute)">'
                             '(heuristics - verify before acting)</span></h2><div class="findings">%s</div></section>' % body)
    for s in rep.sections:
        if all(it["t"] in ("kpis", "findings") for it in s["items"]):
            continue
        parts.append('<section id="%s"><h2>%s<a class="sectop" href="#top">&#8593; page top</a></h2>' % (_slug(s["title"]), _e(s["title"])))

        i, items = 0, s["items"]
        while i < len(items):
            it = items[i]
            t = it["t"]
            if t == "kv":
                rows = []
                while i < len(items) and items[i]["t"] == "kv":
                    rows.append("<dt>%s</dt><dd>%s</dd>" % (_e(items[i]["k"]), _e(items[i]["v"])))
                    i += 1
                parts.append('<dl class="kv">%s</dl>' % "".join(rows))
                continue
            if t == "table":
                cards = []
                while i < len(items) and items[i]["t"] == "table":
                    cards.append(_html_table(items[i]))
                    i += 1
                parts.append('<div class="tables">%s</div>' % "".join(cards))
                continue
            if t == "donut":
                ds = []
                while i < len(items) and items[i]["t"] == "donut":
                    ds.append(_svg_donut(items[i]["title"], items[i]["pairs"], href_for))
                    i += 1
                parts.append('<div class="donuts">%s</div>' % "".join(ds))
                continue
            if t == "flowtraces":
                parts.append('<p class="note">Packet-level view of the most problematic flows (and the biggest ones): '
                             'ladder diagram, throughput and sequence graph. Packet numbers match the original capture file.</p>')
                parts.extend(_html_trace(tr) for tr in it["traces"])
            elif t == "hosts":
                parts.append('<p class="note">Click an IP anywhere in this report to jump to its card.</p>'
                             '<div class="hostlist">%s</div>' % "".join(_host_card(h) for h in it["hosts"]))
            elif t == "note":
                if not it.get("text_only"):
                    parts.append('<p class="note">%s</p>' % _e(it["text"]))
            elif t == "timeline":
                parts.append("<h3>Traffic over time (bandwidth)</h3>" + _svg_timeline(it["per_second"], it.get("info"), rep.meta.get("t0"), rep.meta.get("path", "")))
            elif t == "graph":
                parts.append("<h3>Conversation map (top hosts)</h3>" + _svg_graph(it))
            i += 1
        parts.append("</section>")
    parts.append('</main><a class="totop" href="#top" aria-label="Back to top">&#8593; Top</a><script>%s</script></body></html>' % HTML_JS)
    return "".join(parts)


def pct(n, total):
    return "%.1f%%" % (100.0 * n / total) if total else "-"


def top(counter, n, total=None, label=None):
    rows = []
    total = total if total is not None else sum(counter.values())
    for k, v in counter.most_common(n):
        rows.append((label(k) if label else k, "{:,}".format(v), pct(v, total)))
    return rows


def build_report(a, path, topn, whois=None, traces=None, filter_desc=None):
    W = whois or {}
    R = Report()
    m = a.meta
    R.meta = {"path": path, "format": m.get("format", "?"), "t0": a.first_ts}
    dur = (a.last_ts - a.first_ts) if a.first_ts is not None else 0
    ips = set(a.ip_tx_p) | set(a.ip_rx_p)
    obs = observations(a, dur)
    nhigh = sum(1 for o in obs if o.sev == "high")
    nmed = sum(1 for o in obs if o.sev == "medium")

    # ---- summary
    s = R.section("SUMMARY")
    ipv4 = a.ip_ver.get("IPv4", 0)
    ipv6 = a.ip_ver.get("IPv6", 0)
    rate = human_bps(a.bytes * 8 / dur) if dur > 0 else "-"
    R.kpis(s, [
        ("PACKETS", "{:,}".format(a.pkts), "%s truncated" % pct(a.truncated, a.pkts) if a.truncated else "none truncated"),
        ("DATA", human_bytes(a.bytes), "{:,} bytes".format(a.bytes)),
        ("DURATION", "%.2f s" % dur if dur < 100 else "%.1f min" % (dur / 60), rate + " avg"),
        ("HOSTS", "{:,}".format(len(ips)), "%d IPv4, %d IPv6 pkts" % (ipv4, ipv6) if ipv6 else "IPv4 only"),
        ("FLOWS", "{:,}".format(len(a.flows)), "TCP + UDP"),
        ("FINDINGS", "%d" % len(obs), "%d high, %d medium" % (nhigh, nmed)),
    ])
    R.findings(s, obs)
    R.note(s, "Findings are heuristics - verify before acting.", text_only=True)
    R.kv(s, "File", path)
    R.kv(s, "Format", m.get("format", "?"))
    R.kv(s, "Packets", "{:,}".format(a.pkts))
    R.kv(s, "Bytes on wire", "{:,} ({})".format(a.bytes, human_bytes(a.bytes)))
    if a.first_ts is not None:
        R.kv(s, "First packet", fmt_ts(a.first_ts))
        R.kv(s, "Last packet", fmt_ts(a.last_ts))
        R.kv(s, "Duration", "%.3f s" % dur)
        if dur > 0:
            R.kv(s, "Average rate", "%s, %.1f packets/s" % (human_bps(a.bytes * 8 / dur), a.pkts / dur))
    R.kv(s, "Unique IP addresses", "{:,}".format(len(ips)))
    R.kv(s, "Flows (TCP+UDP)", "{:,}".format(len(a.flows)))
    if filter_desc:
        R.kv(s, "Filter applied", "%s (packet numbers refer to the original file)" % filter_desc)
    if W:
        R.kv(s, "Whois", "%d of %d public IPs resolved (Team Cymru; country = registration country)" % (
            len(W), len(public_ips(ips))))
    if m.get("warning"):
        R.kv(s, "Warning", m["warning"])
    if a.malformed:
        R.kv(s, "Malformed/truncated", ", ".join("%s: %d" % kv for kv in a.malformed.items()))

    # ---- protocol hierarchy
    s = R.section("PROTOCOL HIERARCHY")
    leaf = Counter()
    for stack, n in a.stack_pkts.items():
        leaf[stack.split(":")[-1].upper()] += n
    R.donut(s, "Packets by top protocol", leaf.most_common())
    rows = [(k, "{:,}".format(v), pct(v, a.pkts), human_bytes(a.stack_bytes[k]))
            for k, v in a.stack_pkts.most_common(topn * 2)]
    R.table(s, "Protocol stack per packet", ["Protocols", "Packets", "%", "Bytes"], rows)

    # ---- L1
    s = R.section("LAYER 1 - CAPTURE / PHYSICAL")
    links = ", ".join("%s (%d)" % (LINKTYPES.get(x, "unknown"), x) for x in sorted(m.get("linktypes", [])))
    R.kv(s, "Link type", links or "?")
    R.kv(s, "Snap length", "{:,} bytes".format(m.get("snaplen", 0)))
    R.kv(s, "Timestamp precision", m.get("ts_precision", "?"))
    R.kv(s, "Captured bytes", "{:,}".format(a.cap_bytes))
    R.kv(s, "Truncated packets", "{:,} ({})".format(a.truncated, pct(a.truncated, a.pkts)))
    if a.sizes:
        sz = sorted(a.sizes)
        R.kv(s, "Frame size min/avg/median/max", "%d / %.0f / %d / %d bytes" % (
            sz[0], sum(sz) / len(sz), sz[len(sz) // 2], sz[-1]))
        buckets = [(0, 64), (65, 127), (128, 255), (256, 511), (512, 1023), (1024, 1517), (1518, 10 ** 9)]
        names = ["<=64", "65-127", "128-255", "256-511", "512-1023", "1024-1517", ">=1518 (jumbo/GRO)"]
        cnt = [0] * len(buckets)
        for x in a.sizes:
            for i, (lo, hi) in enumerate(buckets):
                if lo <= x <= hi:
                    cnt[i] += 1
                    break
        R.table(s, "Frame size distribution", ["Size (bytes)", "Packets", "%"],
                [(n, "{:,}".format(c), pct(c, a.pkts)) for n, c in zip(names, cnt) if c])
    if a.per_second:
        peak_sec, peak = max(a.per_second.items(), key=lambda kv: kv[1])
        R.kv(s, "Busiest second", "%s  (%s)" % (fmt_ts(peak_sec)[11:19], human_bps(peak * 8)))
        R.timeline(s, a.per_second, a.sec_info)
    R.note(s, "A capture file does not contain real physical-layer data (speed, duplex, signal, errors);")
    R.note(s, "the values above are what the capture itself records.")

    # ---- L2
    s = R.section("LAYER 2 - DATA LINK (Ethernet / VLAN / ARP)")
    tot_et = sum(a.ethertype.values())
    R.table(s, "EtherTypes", ["Type", "Frames", "%"], top(a.ethertype, topn, tot_et))
    R.table(s, "Frame addressing", ["Kind", "Frames", "%"], top(a.cast, 5))
    R.table(s, "Top source MACs", ["MAC", "Frames", "Bytes"],
            [(k, "{:,}".format(v), human_bytes(a.mac_bytes[k])) for k, v in a.mac_pkts.most_common(topn)])
    if a.vlans:
        R.table(s, "VLAN IDs", ["VLAN", "Frames", "%"], top(a.vlans, topn))
    if a.arp_ops:
        R.table(s, "ARP operations", ["Operation", "Packets", "%"], top(a.arp_ops, 5))
        R.kv(s, "Gratuitous ARP", a.arp_gratuitous)
        unanswered = [ip for ip, n in a.arp_asked.items() if ip not in a.arp_replied and ip != "0.0.0.0"]
        R.kv(s, "ARP requests never answered", "%d target(s)" % len(unanswered))
    if a.neighbors:
        R.table(s, "Discovered neighbours (LLDP / CDP)", ["Proto", "Device", "Port", "Port desc / platform", "Mgmt IP", "Description", "Source MAC"],
                [(n["proto"], n.get("name") or n.get("chassis") or "-", n.get("port") or "-", n.get("port_desc") or n.get("platform") or "-",
                  n.get("mgmt") or "-", n.get("desc") or "-", n["mac"]) for n in a.neighbors.values()][:topn * 2])
    if a.stp_msgs:
        R.kv(s, "Spanning tree BPDUs", ", ".join("%s: %d" % kv for kv in a.stp_msgs.items()))
        R.kv(s, "STP root bridge(s)", "; ".join("%s (%d BPDUs)" % kv for kv in a.stp_roots.most_common(4)) or "-")
        R.kv(s, "STP topology changes / root changes", "%d / %d" % (a.stp_tc, a.stp_root_changes))
    if a.dhcp_xids:
        xs = a.dhcp_xids.values()
        R.kv(s, "DHCP transactions", "%d (DISCOVER w/o OFFER: %d, REQUEST w/o ACK/NAK: %d, NAKs: %d)" % (
            len(a.dhcp_xids), sum(1 for x in xs if 1 in x["types"] and 2 not in x["types"]),
            sum(1 for x in xs if 3 in x["types"] and not (x["types"] & {5, 6})), a.dhcp_nak))
        R.table(s, "DHCP servers (senders of OFFER / ACK)", ["Server", "Messages"], [(k, v) for k, v in a.dhcp_servers.most_common(5)])
    if a.bcast_ps or a.mcast_ps:
        if a.bcast_ps:
            sec, n = max(a.bcast_ps.items(), key=lambda kv: kv[1])
            R.kv(s, "Peak broadcast rate", "%d frames/s at %s UTC" % (n, fmt_ts(sec)[11:19]))
        if a.mcast_ps:
            sec, n = max(a.mcast_ps.items(), key=lambda kv: kv[1])
            R.kv(s, "Peak multicast rate", "%d frames/s at %s UTC" % (n, fmt_ts(sec)[11:19]))
    multi = [(ip, sorted(m)) for ip, m in a.ip_macs.items() if len({x for x in m if not x.startswith(VIRTUAL_MACS)}) > 1
             and ip != "0.0.0.0" and ip_class(ip) in ("private", "link-local")]
    R.table(s, "IPs seen from several MACs (duplicate IP, failover or bridge)", ["IP", "MACs"], [(ip, ", ".join(m)) for ip, m in multi[:topn]])

    # ---- L3
    s = R.section("LAYER 3 - NETWORK (IP / ICMP)")
    R.table(s, "IP versions", ["Version", "Packets", "%"], top(a.ip_ver, 3))
    R.table(s, "Transport / next protocol", ["Protocol", "Packets", "%"], top(a.ip_proto, topn))

    def named(ip):
        n = a.dns_names.get(ip)
        return "%s  (%s)" % (ip, n) if n else ip

    def org(ip):
        w = W.get(ip)
        return "%s  %s (%s)" % (w["asn"], w["org"], w["cc"]) if w else ("private/local" if ip_class(ip) != "public" else "-")

    def with_org(headers, rows):
        """Insert the whois column after 'Class' when whois data is present."""
        if not W:
            return headers, rows
        return headers[:2] + ["AS / Organisation (country)"] + headers[2:], [r[:2] + (org(r[0].split()[0]),) + r[2:] for r in rows]

    def ip_rows(pk, by, n):
        return [(named(ip), ip_class(ip), "{:,}".format(pk[ip]), human_bytes(v), pct(v, a.bytes))
                for ip, v in by.most_common(n)]
    R.table(s, "Top senders (by bytes)", *with_org(["IP", "Class", "Packets", "Bytes", "% of traffic"],
                                                    ip_rows(a.ip_tx_p, a.ip_tx_b, topn)))
    R.table(s, "Top receivers (by bytes)", *with_org(["IP", "Class", "Packets", "Bytes", "% of traffic"],
                                                      ip_rows(a.ip_rx_p, a.ip_rx_b, topn)))
    tot_ip = {ip: a.ip_tx_p[ip] + a.ip_rx_p[ip] for ip in ips}
    tb = {ip: a.ip_tx_b[ip] + a.ip_rx_b[ip] for ip in ips}
    ranked = sorted(tb.items(), key=lambda kv: -kv[1])
    R.table(s, "Most active IPs (sent + received)", *with_org(["IP", "Class", "Packets", "Bytes"],
            [(named(ip), ip_class(ip), "{:,}".format(tot_ip[ip]), human_bytes(v)) for ip, v in ranked[:topn]]))
    if W:
        nets = defaultdict(lambda: [0, 0, set()])
        for ip, v in tb.items():
            key = "%s  %s (%s)" % (W[ip]["asn"], W[ip]["org"], W[ip]["cc"]) if ip in W else (
                "private/local" if ip_class(ip) != "public" else "unresolved public")
            nets[key][0] += v
            nets[key][1] += tot_ip[ip]
            nets[key][2].add(ip)
        def ip_list(members, limit=12):
            ordered = sorted(members, key=lambda x: -tb[x])
            return ", ".join(ordered[:limit]) + (" +%d more" % (len(ordered) - limit) if len(ordered) > limit else "")
        R.table(s, "Top networks / organisations (whois, by bytes)", ["Network", "IPs", "IP addresses", "Packets", "Bytes", "% of traffic"],
                [(k, len(v[2]), ip_list(v[2]), "{:,}".format(v[1]), human_bytes(v[0]), pct(v[0], sum(tb.values())))
                 for k, v in sorted(nets.items(), key=lambda kv: -kv[1][0])[:topn]])
    R.table(s, "Top conversations (IP pairs, by bytes)", ["Host A", "Host B", "Packets", "Bytes"],
            [(x, y, "{:,}".format(a.conv_p[(x, y)]), human_bytes(v)) for (x, y), v in a.conv_b.most_common(topn)])

    # conversation map: nodes = busiest hosts, edges between them, hubs = biggest hosts with their peers
    keep = [ip for ip, _ in ranked[:24]]
    keepset = set(keep)
    nodes = [{"ip": ip, "label": named(ip) if len(named(ip)) <= 34 else ip, "cls": ip_class(ip),
              "bytes": tb[ip], "pkts": tot_ip[ip], "org": org(ip) if W else ""} for ip in keep]
    edges = [(x, y, by, a.conv_p[(x, y)]) for (x, y), by in a.conv_b.most_common(400)
             if x in keepset and y in keepset][:60]
    peers = defaultdict(list)
    for (x, y), by in a.conv_b.items():
        peers[x].append((y, by))
        peers[y].append((x, by))
    hubs = []
    for ip, _ in ranked[:4]:
        pl = sorted(peers[ip], key=lambda p: -p[1])[:5]
        tag = lambda x: named(x) + ("  [%s %s]" % (W[x]["asn"], W[x]["org"]) if x in W else "")
        hubs.append({"ip": ip, "label": tag(ip), "cls": ip_class(ip), "bytes": tb[ip],
                     "peers": [(tag(p), by, a.conv_p[(ip, p) if (ip, p) in a.conv_p else (p, ip)]) for p, by in pl]})
    R.graph(s, nodes, edges, hubs)

    cls = Counter(ip_class(ip) for ip in ips)
    R.table(s, "Address classes (unique IPs)", ["Class", "IPs", "%"], top(cls, 6))
    R.table(s, "TTL / hop limit values", ["TTL", "Packets", "%"], top(a.ttl, 6, label=lambda t: "%d (%s)" % (t, _ttl_guess(t))))
    if a.dscp:
        R.table(s, "DSCP values", ["DSCP", "Packets", "%"], top(a.dscp, 5))
    if a.icmp:
        R.table(s, "ICMP / ICMPv6", ["Message", "Packets", "%"], top(a.icmp, topn))
    R.table(s, "ICMP errors: who complained about which destination", ["Reporting device", "Error", "Original destination", "Count"],
            [(r, k, d, "{:,}".format(c)) for (r, k, d), c in a.icmp_err.most_common(topn)])
    R.kv(s, "Fragmented packets", "{:,}".format(a.frags))
    if a.ipv6_ext:
        R.table(s, "IPv6 extension headers", ["Header", "Packets", "%"], top(a.ipv6_ext, 5))

    # ---- L4
    s = R.section("LAYER 4 - TRANSPORT (TCP / UDP)")
    R.donut(s, "Transport protocols", a.l4.most_common())
    svc = lambda p: "%d  %s" % (p, SERVICES.get(p, ""))
    R.table(s, "Top TCP destination ports (SYNs = connection attempts)", ["Port", "SYNs", "%"],
            top(a.tcp_dport, topn, label=svc))
    R.table(s, "Top UDP destination ports (by packets)", ["Port", "Packets", "%"],
            top(a.udp_dport, topn, label=svc))
    R.table(s, "TCP flag combinations", ["Flags", "Packets", "%"], top(a.tcp_flags, topn))
    tcp_flows = [(k, v) for k, v in a.flows.items() if v[2] == "tcp"]
    udp_flows = [(k, v) for k, v in a.flows.items() if v[2] == "udp"]
    est = sum(1 for fl in a.tcp_flows.values() if fl.established)
    syn_only = sum(1 for fl in a.tcp_flows.values() if fl.syn is not None and fl.synack is None)
    R.kv(s, "TCP flows / UDP flows", "{:,} / {:,}".format(len(tcp_flows), len(udp_flows)))
    R.kv(s, "TCP handshakes completed", "{:,}".format(est))
    R.kv(s, "TCP SYN without reply", "{:,}".format(syn_only))
    R.kv(s, "TCP resets (RST)", "{:,}".format(a.rst))
    tcp_pk = a.l4.get("TCP", 0)
    R.kv(s, "Retransmissions (heuristic)", "{:,} ({} of TCP packets)".format(a.retrans, pct(a.retrans, tcp_pk)))
    R.kv(s, "Out-of-order segments", "{:,} ({} of TCP packets)".format(a.out_of_order, pct(a.out_of_order, tcp_pk)))
    R.kv(s, "Zero-window packets", "{:,}".format(a.zero_win))

    def flow_rows(flows):
        fmt = lambda e: "%s:%d" % e if ":" not in e[0] else "[%s]:%d" % e
        return [(fmt(x), fmt(y), "{:,}".format(v[0]), human_bytes(v[1]))
                for (x, y), v in sorted(flows, key=lambda kv: -kv[1][1])[:topn]]
    R.table(s, "Top TCP flows (by bytes)", ["Endpoint A", "Endpoint B", "Packets", "Bytes"], flow_rows(tcp_flows))
    R.table(s, "Top UDP flows (by bytes)", ["Endpoint A", "Endpoint B", "Packets", "Bytes"], flow_rows(udp_flows))

    # ---- per-flow TCP health
    ranked_flows = sorted(a.tcp_flows.values(), key=lambda fl: -fl.score)

    def flow_row(fl):
        end = fl.end_state().replace("RST by client", "RST>").replace("RST by server", "<RST").replace("no SYN/ACK", "no-reply")
        return (fmt_ep(fl.ep[0]), fmt_ep(fl.ep[1]), "%.2fs" % fl.duration, human_bytes(sum(fl.bytes)), fmt_ms(fl.handshake_ms),
                fmt_ms(fl.rtt_ms), fl.retrans, fl.dupack, fl.zwin, fl.ooo, end, ", ".join(str(p) for p in fl.pk[:6]) or "-")
    fh = ["Client", "Server", "Dur", "Bytes", "HS", "RTT", "Retx", "Dup", "ZW", "OOO", "End", "Packets of interest"]
    R.table(s, "TCP flows needing attention (worst first)", fh, [flow_row(fl) for fl in ranked_flows if fl.score > 0][:topn])
    R.table(s, "Largest TCP flows (by bytes)", fh, [flow_row(fl) for fl in sorted(a.tcp_flows.values(), key=lambda fl: -sum(fl.bytes))[:topn]])
    R.note(s, "HS = handshake time, Retx = retransmissions, Dup = duplicate ACKs, ZW = zero-window, OOO = out-of-order, "
              "End: RST> = reset by client, <RST = reset by server.")
    ends = Counter(fl.end_state().split(" by ")[0] for fl in a.tcp_flows.values())
    R.table(s, "How TCP flows ended", ["State", "Flows", "%"], top(ends, 6))
    beacons = find_beacons(a)
    R.table(s, "Periodic connections (beaconing / polling check)", ["Source", "Destination", "Service", "Count", "Every", "Jitter"],
            [(b_["src"], b_["dst"], "%d/%s %s" % (b_["port"], b_["proto"], SERVICES.get(b_["port"], "")), b_["count"],
              "%.1f s" % b_["mean"], "%.0f%%" % (b_["cv"] * 100)) for b_ in beacons[:topn]])

    # ---- L5/6
    s = R.section("LAYER 5-6 - SESSION / PRESENTATION (TLS)")
    R.kv(s, "ClientHello / ServerHello", "{:,} / {:,}".format(a.tls_clienthello, a.tls_serverhello))
    R.table(s, "Negotiated / offered versions", ["Handshake", "Count", "%"], top(a.tls_hello_versions, 8))
    R.table(s, "TLS record versions", ["Version", "Records", "%"], top(a.tls_versions, 6))
    R.table(s, "Server names (SNI)", ["SNI", "Hellos", "%"], top(a.tls_sni, topn))
    R.table(s, "ALPN protocols offered", ["ALPN", "Count", "%"], top(a.tls_alpn, 6))
    R.table(s, "Server-selected cipher suites (IANA id)", ["Cipher", "Count", "%"], top(a.tls_ciphers, 6))
    R.table(s, "Other TLS records", ["Type", "Records", "%"], top(a.tls_records, 6))
    ref = a.first_ts if a.first_ts is not None else 0

    def cert_rows():
        rows = []
        for c in a.certs[:topn * 2]:
            flags = [x for x, on in (("self-signed", c["self_signed"]), ("EXPIRED", c["not_after"] is not None and c["not_after"] < ref)) if on]
            left = "%d d" % ((c["not_after"] - ref) / 86400) if c["not_after"] is not None else "-"
            rows.append((fmt_ep(c["server"]), c["sni"] or "-", c["subject"].get("CN", "-"),
                         c["issuer"].get("O") or c["issuer"].get("CN") or "-",
                         "%s \u2192 %s" % (fmt_ts(c["not_before"])[:10] if c["not_before"] else "?", fmt_ts(c["not_after"])[:10] if c["not_after"] else "?"),
                         left, c["key"], c["sig"], ", ".join(flags) or "-"))
        return rows
    R.table(s, "Server certificates seen (TLS 1.2 and older; TLS 1.3 encrypts them)",
            ["Server", "SNI", "Subject CN", "Issuer", "Valid", "Days left", "Key", "Signature", "Flags"], cert_rows())
    R.table(s, "TLS client fingerprints (JA3)", ["JA3", "Hellos", "Clients", "Example server names"],
            [(h, n, len(a.ja3_info[h]["clients"]), ", ".join(x for x, _ in a.ja3_info[h]["sni"].most_common(2)) or "-")
             for h, n in a.ja3.most_common(topn)])
    if a.tls_split:
        R.note(s, "%d TLS hellos were split over several packets and could not be fingerprinted." % a.tls_split)
    if not (a.tls_clienthello or a.tls_serverhello or a.tls_versions or a.tls_records):
        R.note(s, "No TLS handshakes found.")
    R.note(s, "QUIC (UDP/443) packets seen: {:,}  (encrypted, SNI not visible here)".format(a.quic))

    # ---- L7
    s = R.section("LAYER 7 - APPLICATION")
    R.kv(s, "DNS queries / responses", "{:,} / {:,}".format(a.dns_queries, a.dns_responses))
    R.table(s, "Top DNS names queried", ["Name", "Queries", "%"], top(a.dns_q, topn))
    R.table(s, "DNS query types", ["Type", "Queries", "%"], top(a.dns_qtype, 8))
    R.table(s, "DNS response codes", ["Code", "Responses", "%"], top(a.dns_rcode, 6))
    R.table(s, "HTTP methods", ["Method", "Requests", "%"], top(a.http_methods, 6))
    R.table(s, "HTTP hosts", ["Host", "Requests", "%"], top(a.http_hosts, topn))
    R.table(s, "HTTP user agents", ["User-Agent", "Requests", "%"], top(a.http_ua, 6))
    R.table(s, "HTTP status codes", ["Status", "Responses", "%"], top(a.http_status, 8))
    R.table(s, "HTTP servers", ["Server", "Responses", "%"], top(a.http_server, 6))
    R.table(s, "HTTP content types", ["Content-Type", "Responses", "%"], top(a.http_ctype, 6))
    R.table(s, "DHCP messages", ["Type", "Count", "%"], top(a.dhcp_types, 8))
    R.table(s, "DHCP client hostnames", ["Hostname", "Count", "%"], top(a.dhcp_hosts, 8))
    R.table(s, "DHCP vendor classes", ["Vendor", "Count", "%"], top(a.dhcp_vendor, 5))
    R.table(s, "SSDP", ["Message", "Count", "%"], top(a.ssdp, 5))
    R.table(s, "Service banners", ["Banner", "Count", "%"], top(a.banners, 8))
    if a.ntp:
        R.kv(s, "NTP packets", "{:,}".format(a.ntp))

    # ---- latency
    s = R.section("LATENCY")
    hs_ms = [fl.handshake_ms for fl in a.tcp_flows.values() if fl.handshake_ms is not None]
    rtt_ms = [fl.rtt_ms for fl in a.tcp_flows.values() if fl.rtt_ms is not None]
    lat_rows = []
    for name, vals in (("TCP handshake (SYN \u2192 SYN/ACK)", hs_ms), ("TCP data \u2192 ACK (RTT estimate per flow)", rtt_ms),
                       ("DNS query \u2192 response", [x[0] for x in a.dns_lat]),
                       ("TLS ClientHello \u2192 ServerHello", [x[0] for x in a.tls_lat]),
                       ("HTTP request \u2192 response", [x[0] for x in a.http_tx])):
        st_ = lat_stats(vals)
        if st_:
            lat_rows.append((name, "{:,}".format(st_[0]), fmt_ms(st_[1]), fmt_ms(st_[2]), fmt_ms(st_[3]), fmt_ms(st_[4])))
    R.table(s, "Response times", ["Metric", "Samples", "Min", "Median", "95th pct", "Max"], lat_rows)
    horizon = (a.last_ts or 0) - 2
    R.kv(s, "DNS queries without a response", "%d" % sum(1 for v in a.dns_pending.values() if v[0] < horizon))
    by_srv = defaultdict(list)
    for ms_, name, server, rc, qp, rp in a.dns_lat:
        by_srv[server].append((ms_, rc))
    R.table(s, "DNS latency by resolver", ["Resolver", "Queries", "Median", "95th pct", "Max", "Errors"],
            [(srv, len(v), fmt_ms(pctl(sorted(x for x, _ in v), 50)), fmt_ms(pctl(sorted(x for x, _ in v), 95)),
              fmt_ms(max(x for x, _ in v)), sum(1 for _, rc in v if rc != "NOERROR"))
             for srv, v in sorted(by_srv.items(), key=lambda kv: -len(kv[1]))[:topn]])
    R.table(s, "Slowest DNS queries", ["Time", "Name", "Resolver", "Result", "Packets"],
            [(fmt_ms(x[0]), x[1], x[2], x[3], "%d \u2192 %d" % (x[4], x[5])) for x in sorted(a.dns_lat, reverse=True)[:topn]])
    R.table(s, "Slowest HTTP transactions", ["Time", "Host / path", "Status", "Server", "Packets"],
            [(fmt_ms(x[0]), "%s%s" % (x[1], x[2]), x[3] or "-", x[4], "%d \u2192 %d" % (x[5], x[6])) for x in sorted(a.http_tx, reverse=True)[:topn]])
    R.table(s, "Slowest TLS handshakes (ClientHello \u2192 ServerHello)", ["Time", "Server name", "Server", "Version", "Packets"],
            [(fmt_ms(x[0]), x[1] or "-", x[2], x[3], "%d \u2192 %d" % (x[4], x[5])) for x in sorted(a.tls_lat, reverse=True)[:topn]])
    R.table(s, "Slowest TCP handshakes", ["Time", "Client", "Server", "SNI", "First packet"],
            [(fmt_ms(fl.handshake_ms), fmt_ep(fl.ep[0]), fmt_ep(fl.ep[1]), fl.sni or "-", fl.n0)
             for fl in sorted((x for x in a.tcp_flows.values() if x.handshake_ms is not None), key=lambda x: -x.handshake_ms)[:topn]])
    R.note(s, "Handshake and RTT values are measured at the capture point: at the client they equal the network round trip,")
    R.note(s, "at the server they mostly show the client-side delay. Compare both ends when in doubt.")

    # ---- path / MTU
    s = R.section("PATH / MTU / TCP OPTIONS")
    mss_rows = [(side, m, c, pct(c, sum(cnt.values()))) for side, cnt in a.tcp_mss.items() for m, c in cnt.most_common(6)]
    R.table(s, "TCP MSS announced", ["Side", "MSS", "SYNs", "%"], mss_rows)
    ws_rows = [(side, w_, c, pct(c, sum(cnt.values()))) for side, cnt in a.tcp_ws.items() for w_, c in cnt.most_common(6)]
    R.table(s, "TCP window scale announced", ["Side", "Shift", "SYNs", "%"], ws_rows)
    R.table(s, "TCP options negotiated on SYNs", ["Option", "Count"], [(k, v) for k, v in sorted(a.tcp_opts.items())])
    R.table(s, "IPv4 Don't-Fragment bit", ["DF", "Packets", "%"], top(a.df, 3))
    R.table(s, "Path-MTU reports (ICMP fragmentation needed / packet too big)", ["Reporting device", "Next-hop MTU", "Original sender", "Original destination", "Packet"],
            [(r_, m_, o_, d_, p_) for r_, m_, o_, d_, p_ in a.pmtu[:topn]])
    holes = [fl for fl in a.tcp_flows.values() if fl.blackhole]
    R.table(s, "Possible PMTU black holes (full-size segments retransmitted)", ["Client", "Server", "Largest segment", "Retransmissions", "Packets"],
            [(fmt_ep(fl.ep[0]), fmt_ep(fl.ep[1]), fl.max_seg, fl.retrans, ", ".join(str(p) for p in fl.pk[:6])) for fl in holes[:topn]])
    R.kv(s, "Largest TCP segment seen", "%d bytes" % max((fl.max_seg for fl in a.tcp_flows.values()), default=0))
    R.kv(s, "Frames larger than 1514 bytes", "{:,} (GRO/TSO offload in the capture, or jumbo frames)".format(sum(1 for x in a.sizes if x > 1514)))
    R.note(s, "Pair this with 'ipx --mtu <host>' to measure the real path MTU towards a suspect destination.")

    # ---- flow traces (second pass over the file)
    if traces:
        s = R.section("FLOW TRACES (ladder diagrams)")
        R.flowtraces(s, traces)

    # ---- host cards (link targets for every IP in the HTML report)
    s = R.section("HOSTS")
    hosts = []
    for ip, _ in ranked[:min(60, max(25, topn * 3))]:
        pl = sorted(peers[ip], key=lambda x: -x[1])[:6]
        mention = re.compile(r"(?<![\w.:])" + re.escape(ip) + r"(?![\w.:])")
        hosts.append({
            "ip": ip, "name": a.dns_names.get(ip, ""), "cls": ip_class(ip), "org": org(ip) if W else "",
            "tx_pkts": a.ip_tx_p[ip], "tx_bytes": a.ip_tx_b[ip], "rx_pkts": a.ip_rx_p[ip], "rx_bytes": a.ip_rx_b[ip],
            "peers": [(named(q), by, a.conv_p[(ip, q) if (ip, q) in a.conv_p else (q, ip)]) for q, by in pl],
            "protocols": a.ip_stacks[ip].most_common(6),
            "services": a.ip_services[ip].most_common(6),
            "sni": a.ip_sni[ip].most_common(5), "http": a.ip_http[ip].most_common(5), "dns": a.ip_dnsq[ip].most_common(5),
            "findings": [o for o in obs if mention.search(o.text)],
        })
    R.hosts(s, hosts)
    R.meta["linkable"] = {h["ip"] for h in hosts}
    return R


def _ttl_guess(t):
    if t > 128:
        return "started at 255: network gear/Solaris"
    if t > 64:
        return "started at 128: likely Windows"
    if t > 32:
        return "started at 64: likely Linux/macOS/Android"
    return "low: multicast/link-local or many hops"


def _ipf(ip, field="addr"):
    return ("ipv6." if ":" in ip else "ip.") + field


def fmt_ep(ep):
    return "[%s]:%d" % ep if ":" in ep[0] else "%s:%d" % ep


BENIGN_PERIODIC = {123, 53, 5353, 1900, 137, 138, 67, 68, 5355, 546, 547, 161}
VIRTUAL_MACS = ("00:00:5e:00:01", "00:00:5e:00:02", "00:00:0c:07:ac", "00:07:b4:00")


def find_beacons(a):
    """Connections from one host to one service at regular intervals (beaconing / polling)."""
    res = []
    for (src, dst, port, proto), ts in a.conn_times.items():
        if len(ts) < 6 or src == dst:
            continue
        ts = sorted(ts)
        iv = [y - x for x, y in zip(ts, ts[1:])]
        mean = sum(iv) / len(iv)
        if mean < 1.0 or mean > 4000:
            continue
        cv = math.sqrt(sum((x - mean) ** 2 for x in iv) / len(iv)) / mean
        if cv <= 0.2:
            res.append({"src": src, "dst": dst, "port": port, "proto": proto, "count": len(ts), "mean": mean, "cv": cv})
    res.sort(key=lambda r: (-r["count"], r["cv"]))
    return res


def observations(a, dur):
    """Heuristic findings with evidence: Finding(severity, text, wireshark filter, packet numbers, total)."""
    out = []
    now = datetime.now(timezone.utc).timestamp()

    def add(sev, text, filt="", keys=(), pkts=None):
        if pkts is not None:
            u = sorted(set(pkts))
            out.append(Finding(sev, text, filt, u[:12], len(u)))
        else:
            merged = sorted({p for k in keys for p in a.ev.get(k, [])})
            out.append(Finding(sev, text, filt, merged[:12], sum(a.evn.get(k, 0) for k in keys)))

    # ---- TCP behaviour
    for src, targets in a.syn_targets.items():
        unanswered = [t for t in targets if (src, t[0], t[1]) not in a.answered]
        hosts = {t[0] for t in unanswered}
        ports = {t[1] for t in unanswered}
        if len(unanswered) >= 20 and len(unanswered) >= 0.8 * len(targets):
            kind = "port scan" if len(ports) > len(hosts) else "host sweep"
            add("high", "Possible TCP %s from %s: %d unanswered SYNs to %d host(s) / %d port(s)." % (
                kind, src, len(unanswered), len(hosts), len(ports)),
                "%s==%s && tcp.flags.syn==1 && tcp.flags.ack==0" % (_ipf(src, "src"), src), ("scan:" + src,))
    flows = list(a.tcp_flows.values())
    tcp_pk = a.l4.get("TCP", 0)
    if tcp_pk > 100 and a.retrans / tcp_pk > 0.02:
        add("medium", "High TCP retransmission rate: %s of TCP packets (possible loss/congestion)." % pct(a.retrans, tcp_pk),
            "tcp.analysis.retransmission", ("retrans",))
    if a.dupacks >= 20 and tcp_pk > 100 and a.dupacks / tcp_pk > 0.01:
        add("medium", "%d duplicate ACKs (%s of TCP packets): packets are being lost or reordered on the path." % (
            a.dupacks, pct(a.dupacks, tcp_pk)), "tcp.analysis.duplicate_ack", ("dupack",))
    if tcp_pk > 100 and a.rst / tcp_pk > 0.05:
        add("medium", "Many TCP resets: %s of TCP packets (refused ports, aborted sessions or a scan)." % pct(a.rst, tcp_pk),
            "tcp.flags.reset==1", ("rst",))
    if a.zero_win:
        add("medium", "%d zero-window packets: a receiver could not keep up." % a.zero_win, "tcp.analysis.zero_window", ("zerowin",))
    noreply = [fl for fl in flows if fl.syn is not None and fl.synack is None and fl.rst == 0]
    if len(noreply) >= 5:
        targets = Counter(fl.ep[1][0] for fl in noreply)
        add("medium", "%d TCP connection attempts got no SYN/ACK or RST (silent drop by a firewall, or host down); most to %s." % (
            len(noreply), targets.most_common(1)[0][0]),
            "tcp.flags.syn==1 && tcp.flags.ack==0 && !tcp.analysis.retransmission", pkts=[fl.n0 for fl in noreply if fl.n0])
    slow_hs = sorted((fl for fl in flows if fl.handshake_ms is not None and fl.handshake_ms > 500), key=lambda fl: -fl.handshake_ms)
    if slow_hs:
        add("info", "%d TCP handshakes took over 500 ms (slowest %s to %s): high path latency or a loaded server." % (
            len(slow_hs), fmt_ms(slow_hs[0].handshake_ms), fmt_ep(slow_hs[0].ep[1])),
            "tcp.analysis.initial_rtt > 0.5", pkts=[fl.n0 for fl in slow_hs if fl.n0])
    # ---- path MTU
    groups = defaultdict(list)
    for rep_ip, mtu, osrc, odst, pkt in a.pmtu:
        groups[(rep_ip, mtu)].append((odst, pkt))
    for (rep_ip, mtu), lst in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        add("high", "%s reported next-hop MTU %d (fragmentation needed / packet too big) %d time(s) for traffic to %s - "
            "a path MTU problem if large packets are being dropped." % (rep_ip, mtu, len(lst), lst[0][0]),
            "icmp.type == 3 && icmp.code == 4 || icmpv6.type == 2", pkts=[p for _, p in lst])
    for fl in flows:
        if fl.blackhole:
            add("medium", "Possible path-MTU black hole: %s -> %s retransmitted full-size segments %d times (largest segment %d bytes)." % (
                fmt_ep(fl.ep[0]), fmt_ep(fl.ep[1]), fl.retrans, fl.max_seg), flow_filter(fl.ep[0], fl.ep[1]), pkts=fl.pk)
    csyn = a.tcp_mss["client (SYN)"]
    low = sum(c for m, c in csyn.items() if m < 1400)
    if csyn and low and low / sum(csyn.values()) >= 0.1:
        lowest = min(m for m in csyn if m < 1400)
        add("info", "%s of client SYNs announce an MSS below 1400 (lowest %d): a tunnel/VPN, PPPoE or an MSS clamp is on the path." % (
            pct(low, sum(csyn.values())), lowest), "tcp.flags.syn==1 && tcp.options.mss_val < 1400")
    # ---- cleartext
    clear_filters = {"FTP login": 'ftp.request.command == "USER" || ftp.request.command == "PASS"', "Telnet session": "telnet",
                     "SMTP AUTH": 'smtp.req.command == "AUTH"', "POP3 login": "pop", "IMAP login": "imap",
                     "HTTP Basic auth": "http.authbasic", "HTTP POST with password field": 'http.request.method == "POST"'}
    for what, n in a.cleartext.items():
        hosts = ", ".join(sorted(a.cleartext_hosts[what])[:5])
        add("high", "Cleartext traffic: %s (%d packets) to/from %s - credentials/data may be readable." % (what, n, hosts),
            clear_filters.get(what, ""), ("clear:" + what,))
    # ---- TLS
    for what, n in a.tls_old.items():
        add("medium", "Deprecated TLS: %d handshake(s) where the %s." % (n, what), "tls.handshake.version < 0x0303", ("tls-old",))
    ref = a.first_ts if a.first_ts is not None else now
    for c in a.certs:
        cn = c["subject"].get("CN", "?")
        srv = fmt_ep(c["server"])
        flt = "tls.handshake.type == 11 && %s==%s" % (_ipf(c["server"][0]), c["server"][0])
        if c["not_after"] is not None and c["not_after"] < ref:
            add("high", "Expired certificate for %s (CN %s) on %s: expired %s." % (c["sni"] or cn, cn, srv, fmt_ts(c["not_after"])[:10]), flt, pkts=[c["pkt"]])
        elif c["not_after"] is not None and c["not_after"] - ref < 30 * 86400:
            add("medium", "Certificate for %s (CN %s) on %s expires within 30 days (%s)." % (c["sni"] or cn, cn, srv, fmt_ts(c["not_after"])[:10]), flt, pkts=[c["pkt"]])
        if c["not_before"] is not None and c["not_before"] > ref + 86400:
            add("medium", "Certificate for %s on %s is not valid yet (starts %s)." % (cn, srv, fmt_ts(c["not_before"])[:10]), flt, pkts=[c["pkt"]])
        if c["self_signed"]:
            add("medium", "Self-signed certificate (CN %s) presented by %s." % (cn, srv), flt, pkts=[c["pkt"]])
        if "sha1" in c["sig"].lower() or "md5" in c["sig"].lower():
            add("medium", "Weak certificate signature %s (CN %s on %s)." % (c["sig"], cn, srv), flt, pkts=[c["pkt"]])
        if c["key"].startswith("RSA") and int(c["key"].split()[1]) < 2048:
            add("medium", "Short RSA key (%s) in certificate CN %s on %s." % (c["key"], cn, srv), flt, pkts=[c["pkt"]])
        names = c["san"] or ([cn] if cn != "?" else [])
        if c["sni"] and names and not host_matches(c["sni"], names):
            add("medium", "Certificate name mismatch: client asked for %s but %s presented %s." % (
                c["sni"], srv, ", ".join(names[:3])), flt, pkts=[c["pkt"]])
    # ---- DNS
    nx = a.dns_rcode.get("NXDOMAIN", 0)
    if a.dns_responses >= 20 and nx / a.dns_responses > 0.3:
        add("medium", "%s of DNS responses are NXDOMAIN (possible DGA/malware or misconfiguration)." % pct(nx, a.dns_responses),
            "dns.flags.rcode == 3", ("nxdomain",))
    if len(a.dns_long) >= 5:
        add("medium", "%d DNS queries with very long names (e.g. %s) - check for DNS tunnelling." % (len(a.dns_long), a.dns_long[0][:60]),
            "dns.qry.name.len > 60", ("dns-long",))
    if a.dns_qtype.get("TXT", 0) > 20 or a.dns_qtype.get("ANY", 0) > 5:
        add("info", "Unusual DNS types: TXT=%d ANY=%d." % (a.dns_qtype.get("TXT", 0), a.dns_qtype.get("ANY", 0)),
            "dns.qry.type == 16 || dns.qry.type == 255")
    horizon = (a.last_ts or 0) - 2
    lost = [v for v in a.dns_pending.values() if v[0] < horizon]
    if len(lost) >= 3:
        srv = Counter(v[4] for v in lost).most_common(1)[0][0]
        add("medium", "%d DNS queries got no response (most to %s): resolver down or blocked, or the replies are not in this capture." % (
            len(lost), srv), "dns.flags.response == 0 && !dns.response_in", pkts=[v[3] for v in lost])
    bysrv = defaultdict(list)
    for ms_, name, server, rc, qp, rp in a.dns_lat:
        bysrv[server].append((ms_, rp))
    for server, lst in bysrv.items():
        if len(lst) >= 5:
            med = pctl(sorted(x for x, _ in lst), 50)
            if med > 150:
                add("medium", "Slow DNS resolver %s: median response %s over %d queries." % (server, fmt_ms(med), len(lst)),
                    "dns.time > 0.15", pkts=[p for _, p in sorted(lst, reverse=True)[:12]])
    # ---- HTTP / TLS timing
    e5 = [t for t in a.http_tx if t[3].startswith("5")]
    if len(e5) >= 5:
        add("medium", "%d HTTP 5xx server errors (e.g. %s %s)." % (len(e5), e5[0][3], e5[0][1]), "http.response.code >= 500", pkts=[t[6] for t in e5])
    if len(a.http_tx) >= 5:
        st = lat_stats([t[0] for t in a.http_tx])
        if st[3] > 1000:
            add("info", "Slow HTTP responses: 95th percentile %s (median %s) over %d requests." % (fmt_ms(st[3]), fmt_ms(st[2]), st[0]),
                "http.time > 1", pkts=[t[6] for t in sorted(a.http_tx, reverse=True)[:12]])
    if len(a.tls_lat) >= 3:
        st = lat_stats([t[0] for t in a.tls_lat])
        if st[2] > 1000:
            add("info", "Slow TLS handshakes: median ClientHello->ServerHello %s over %d handshakes." % (fmt_ms(st[2]), st[0]),
                "tls.handshake.type == 2", pkts=[t[5] for t in sorted(a.tls_lat, reverse=True)[:12]])
    # ---- layer 2
    for ip, macs in a.arp_map.items():
        if len(macs) > 1:
            add("high", "ARP: %s claimed by %d different MACs (%s) - conflict or ARP spoofing." % (ip, len(macs), ", ".join(sorted(macs))),
                "arp.src.proto_ipv4 == %s" % ip, ("arpconf:" + ip,))
    for ip, macs in a.ip_macs.items():
        real = {m for m in macs if not m.startswith(VIRTUAL_MACS)}
        if len(real) > 1 and ip != "0.0.0.0" and ip_class(ip) in ("private", "link-local"):
            add("medium", "IP %s is sent from %d different MACs (%s) - duplicate IP, bonding/failover or a bridge." % (
                ip, len(real), ", ".join(sorted(real))), "%s==%s" % (_ipf(ip, "src"), ip))
    if a.arp_gratuitous > 5:
        add("info", "%d gratuitous ARP packets." % a.arp_gratuitous, "arp.isgratuitous", ("arp-gratuitous",))
    for spa, tg in a.arp_targets.items():
        if len(tg) >= 50:
            add("medium", "ARP sweep: %s asked for %d different IPs." % (spa, len(tg)), "arp.src.proto_ipv4 == %s && arp.opcode == 1" % spa)
    if a.arp_req_ps and max(a.arp_req_ps.values()) >= 100:
        sec, n = max(a.arp_req_ps.items(), key=lambda kv: kv[1])
        add("medium", "ARP storm candidate: %d ARP requests in one second (%s UTC)." % (n, fmt_ts(sec)[11:19]), "arp.opcode == 1")
    silent = [ip for ip, n in a.arp_asked.items() if n >= 3 and ip not in a.arp_replied and ip != "0.0.0.0"]
    if silent:
        add("medium", "%d IP(s) were ARPed repeatedly but never answered (host down, wrong subnet or filtered), e.g. %s." % (len(silent), silent[0]),
            "arp.opcode == 1", pkts=[p for ip in silent for p in a.arp_req_pkts[ip]])
    storm = max(a.bcast_ps.items(), key=lambda kv: kv[1], default=(0, 0))
    if storm[1] >= 500:
        add("medium", "Broadcast storm candidate: %d broadcast frames in one second (%s UTC)." % (storm[1], fmt_ts(storm[0])[11:19]),
            "eth.dst == ff:ff:ff:ff:ff:ff")
    nodisc = [x for x in a.dhcp_xids.values() if 1 in x["types"] and 2 not in x["types"]]
    if nodisc:
        add("medium", "%d DHCP DISCOVER(s) got no OFFER (no DHCP server reachable?), e.g. client %s." % (len(nodisc), nodisc[0]["mac"]),
            "dhcp.option.dhcp == 1", pkts=[x["pkt"] for x in nodisc])
    noack = [x for x in a.dhcp_xids.values() if 3 in x["types"] and not (x["types"] & {5, 6})]
    if noack:
        add("medium", "%d DHCP REQUEST(s) got neither ACK nor NAK." % len(noack), "dhcp.option.dhcp == 3", pkts=[x["pkt"] for x in noack])
    if a.dhcp_nak:
        add("medium", "%d DHCP NAK(s): clients were refused their requested address." % a.dhcp_nak, "dhcp.option.dhcp == 6", ("dhcp-nak",))
    if len(a.dhcp_servers) > 1:
        add("high", "Multiple DHCP servers answered: %s - a rogue or second DHCP server on the segment?" % ", ".join(sorted(a.dhcp_servers)),
            "dhcp.option.dhcp == 2 || dhcp.option.dhcp == 5")
    if a.stp_root_changes:
        add("medium", "Spanning-tree root bridge changed %d time(s); roots seen: %s." % (a.stp_root_changes, "; ".join(a.stp_roots)),
            "stp", ("stp-root",))
    if a.stp_tc >= 3:
        add("medium", "%d spanning-tree topology-change notifications (flapping port or loop?)." % a.stp_tc, "stp.flags.tc == 1", ("stp-tc",))
    # ---- ICMP / fragmentation / capture quality
    echo = a.icmp.get("echo-request (type 8 code 0)", 0)
    if echo > 100 and dur > 0 and echo / dur > 50:
        add("medium", "ICMP echo-request rate %.0f/s (ping flood or sweep)." % (echo / dur), "icmp.type == 8")
    if a.udp_port_unreach > 20:
        add("info", "%d ICMP port-unreachable messages (UDP to closed ports, possible UDP scan)." % a.udp_port_unreach,
            "icmp.type == 3 && icmp.code == 3", ("icmp-unreach",))
    if a.frags > 0:
        add("info", "%d fragmented IP packets (check MTU issues or evasion)." % a.frags, "ip.flags.mf == 1 || ip.frag_offset > 0", ("frag",))
    # ---- periodic connections
    for bc in find_beacons(a)[:8]:
        benign = bc["port"] in BENIGN_PERIODIC
        sev = "info" if benign or ip_class(bc["dst"]) != "public" else "medium"
        add(sev, "Periodic %s connections %s -> %s:%d every %.1f s (%d times, jitter %.0f%%)%s." % (
            bc["proto"].upper(), bc["src"], bc["dst"], bc["port"], bc["mean"], bc["count"], bc["cv"] * 100,
            " - normal for this service" if benign else " - polling or beaconing; check what the client is"),
            "%s==%s && %s==%s" % (_ipf(bc["src"]), bc["src"], _ipf(bc["dst"]), bc["dst"]))
    if a.truncated:
        add("info", "%d packets are truncated by the snap length; payload analysis is incomplete for them." % a.truncated,
            "frame.cap_len < frame.len")
    if a.malformed:
        add("info", "Malformed packets: " + ", ".join("%s (%d)" % kv for kv in a.malformed.items()) + ".", "_ws.malformed")
    return out


# ------------------------------------------------------------------ flow traces (second pass)

def pick_flows(a, limit=6):
    """Worst TCP flows first, then the biggest ones."""
    items = list(a.tcp_flows.items())
    chosen = sorted((kv for kv in items if kv[1].score > 0), key=lambda kv: -kv[1].score)[:4]
    for kv in sorted(items, key=lambda kv: -sum(kv[1].bytes)):
        if len(chosen) >= limit or sum(1 for c in chosen if c[1].score <= 0) >= 2:
            break
        if kv not in chosen and sum(kv[1].bytes) > 0:
            chosen.append(kv)
    return [k for k, _ in chosen]


def _pkt_label(flags, rs, ra, plen):
    s = "[%s]" % flags_str(flags).replace("+", ",")
    out = "%s seq=%d" % (s, rs)
    if ra is not None:
        out += " ack=%d" % ra
    if plen:
        out += " len=%d" % plen
    return out


def _rel(t, t0):
    d = (t - t0) * 1000.0 if t is not None and t0 is not None else 0.0
    return "+%.1f ms" % d if d < 1000 else "+%.3f s" % (d / 1000.0)


def build_traces(path, a, pf_kwargs, keys, cmd_path):
    """Re-read the capture and collect packet events for the chosen TCP flows."""
    if not keys:
        return []
    sel = {k: {"flow": TcpFlow(a.tcp_flows[k].ep[0], a.tcp_flows[k].ep[1]), "ev": [], "pts": [], "seq0": [None, None], "t0": None}
           for k in keys}
    pf = PacketFilter(**pf_kwargs)
    n = 0
    try:
        fh = open_capture(path)
        with fh:
            for ts, caplen, origlen, link, data in iter_packets(fh, {}):
                n += 1
                if pf.active and not pf.match(ts, link, data):
                    continue
                q = quick_parse(link, data)
                if q is None or q.proto != "tcp":
                    continue
                x, y = (q.src, q.sport), (q.dst, q.dport)
                s = sel.get((x, y) if x <= y else (y, x))
                if s is None:
                    continue
                seq, ack, flags, win, plen = q.tcp
                fl = s["flow"]
                d = fl.direction(q.src, q.sport)
                marks = fl.update(ts, n, d, seq, ack, flags, win, plen, origlen)
                if s["seq0"][d] is None:
                    s["seq0"][d] = seq
                rs = (seq - s["seq0"][d]) & MASK32
                ra = ((ack - s["seq0"][1 - d]) & MASK32) if (flags & 0x10 and s["seq0"][1 - d] is not None) else None
                if s["t0"] is None:
                    s["t0"] = ts
                if len(s["ev"]) < 4000:
                    s["ev"].append((n, ts, d, flags, rs, ra, plen, win, tuple(marks)))
                if plen and ts is not None and len(s["pts"]) < 4000:
                    s["pts"].append((ts - s["t0"], d, rs + plen, "retransmission" in marks))
    except (OSError, EOFError, CaptureError):
        pass
    traces = []
    for i, k in enumerate(keys, 1):
        s, fl = sel[k], a.tcp_flows[k]
        ev = s["ev"]
        if not ev:
            continue
        base = set(range(min(8, len(ev)))) | set(range(max(0, len(ev) - 3), len(ev)))
        flagged = [j for j, e in enumerate(ev) if e[8] and j not in base]
        order = sorted(base | set(flagged[:max(0, 30 - len(base))]))
        ladder = []
        for j in order:
            e = ev[j]
            m = e[8]
            cls = "r" if ("retransmission" in m or "rst" in m) else "o" if ("dup-ack" in m or "out-of-order" in m) else "p" if "zero-window" in m else ""
            ladder.append({"n": e[0], "t": _rel(e[1], s["t0"]), "d": e[2], "label": _pkt_label(e[3], e[4], e[5], e[6]),
                           "cls": cls, "mark": ", ".join(m)})
        t0 = s["t0"] or 0.0
        tmax = max((e[1] for e in ev if e[1] is not None), default=t0)
        span = max(tmax - t0, 1e-6)
        nb = 60
        bins = ([0] * nb, [0] * nb)
        for e in ev:
            if e[6] and e[1] is not None:
                bins[e[2]][min(nb - 1, int((e[1] - t0) / span * nb))] += e[6]
        c, sv = fl.ep
        sni = " (%s)" % fl.sni if fl.sni else ""
        stats = ("RTT %s, handshake %s, duration %.2f s, %d packets / %s, retransmissions %d, dup-ACKs %d, zero-window %d, out-of-order %d, ended: %s"
                 % (fmt_ms(fl.rtt_ms), fmt_ms(fl.handshake_ms), fl.duration, sum(fl.pkts), human_bytes(sum(fl.bytes)),
                    fl.retrans, fl.dupack, fl.zwin, fl.ooo, fl.end_state()))
        traces.append({
            "title": "Flow %d: %s → %s%s" % (i, fmt_ep(c), fmt_ep(sv), sni),
            "client": fmt_ep(c), "server": fmt_ep(sv), "filter": flow_filter(c, sv), "stats_line": stats,
            "stats": {"rtt_ms": fl.rtt_ms, "handshake_ms": fl.handshake_ms, "retransmissions": fl.retrans, "dup_acks": fl.dupack,
                      "zero_window": fl.zwin, "out_of_order": fl.ooo, "end": fl.end_state(), "packets": sum(fl.pkts), "bytes": sum(fl.bytes)},
            "extract": "pcap_analyzer.py %s --flow %s,%s --extract flow.pcap" % (shlex.quote(cmd_path), fmt_ep(c), fmt_ep(sv)),
            "ladder": ladder, "omitted": max(0, len(ev) - len(ladder)),
            "tput": (bins, t0, span / nb), "pts": s["pts"],
        })
    return traces


# ------------------------------------------------------------------ main

def parse_endpoint(s):
    m = re.fullmatch(r"\[([0-9a-fA-F:.]+)\]:(\d+)", s.strip())
    if m:
        return m.group(1), int(m.group(2))
    host, _, port = s.strip().rpartition(":")
    if not host or not port.isdigit():
        raise ValueError("bad endpoint '%s' (use IP:PORT or [IPv6]:PORT)" % s)
    return host, int(port)


def main():
    ap = argparse.ArgumentParser(description="Analyze a pcap/pcapng capture and print a text report "
                                 "(top IPs, protocols, layers 1-7, findings), optionally as an HTML report.")
    ap.add_argument("pcap", help="capture file (.pcap, .pcapng, optionally .gz)")
    ap.add_argument("-n", "--top", type=int, default=10, help="rows per top-list (default 10)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report with charts")
    ap.add_argument("-q", "--quiet", action="store_true", help="with --html/-o/--extract: do not print the report to the terminal")
    ap.add_argument("-o", "--output", help="write the plain-text report to this file as well")
    ap.add_argument("--whois", action="store_true",
                    help="look up ASN/organisation/country of the public IPs (sends them to whois.cymru.com)")
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                    help="colors in terminal output (default auto; NO_COLOR is respected)")
    g = ap.add_argument_group("filters (applied while reading; packet numbers stay those of the original file)")
    g.add_argument("--host", action="append", default=[], metavar="IP", help="only packets to/from this IP (repeatable)")
    g.add_argument("--port", action="append", type=int, default=[], metavar="N", help="only TCP/UDP packets using this port (repeatable)")
    g.add_argument("--proto", action="append", default=[], metavar="P", help="only tcp, udp, icmp, icmpv6 or arp (repeatable)")
    g.add_argument("--flow", action="append", default=[], metavar="A,B",
                   help="only one conversation: IP:PORT,IP:PORT or [IPv6]:PORT,... (repeatable)")
    g.add_argument("--from", dest="t_from", metavar="TIME", help="start of window: +SECONDS after the first packet, HH:MM:SS or 'YYYY-MM-DD HH:MM:SS' (UTC)")
    g.add_argument("--to", dest="t_to", metavar="TIME", help="end of window (same formats as --from)")
    ap.add_argument("--extract", metavar="FILE", help="write the packets that pass the filters to a new pcap (open it in Wireshark)")
    ap.add_argument("--no-trace", action="store_true", help="skip the flow-trace pass (it reads the capture a second time)")
    args = ap.parse_args()

    try:
        flows = []
        for spec in args.flow:
            parts = spec.split(",")
            if len(parts) != 2:
                raise ValueError("bad --flow '%s' (use IP:PORT,IP:PORT)" % spec)
            flows.append((parse_endpoint(parts[0]), parse_endpoint(parts[1])))
        pf_kwargs = dict(hosts=args.host, ports=args.port, protos=args.proto, flows=flows,
                         t_from=PacketFilter.parse_time(args.t_from, None), t_to=PacketFilter.parse_time(args.t_to, None))
    except ValueError as e:
        sys.exit("error: %s" % e)
    pf = PacketFilter(**pf_kwargs)
    if args.extract and not pf.active:
        sys.exit("error: --extract needs at least one filter (--host/--port/--proto/--flow/--from/--to)")

    a = Analyzer()
    writer = None
    try:
        fh = open_capture(args.pcap)
    except OSError as e:
        sys.exit("error: %s" % e)
    try:
        with fh:
            n = 0
            for pkt in iter_packets(fh, a.meta):
                n += 1
                if pf.active and not pf.match(pkt[0], pkt[3], pkt[4]):
                    continue
                if args.extract:
                    if writer is None:
                        writer = PcapWriter(args.extract, pkt[3])
                    writer.write(*pkt)
                a.add(*pkt, n=n)
    except CaptureError as e:
        sys.exit("error: %s" % e)
    except (EOFError, OSError) as e:
        a.meta["warning"] = "read error: %s" % e
    if writer:
        writer.close()
        print("%d packets written to %s%s" % (writer.n, args.extract, " (%d skipped: different link type)" % writer.skipped if writer.skipped else ""),
              file=sys.stderr)
    if a.pkts == 0:
        sys.exit("error: no packets %s in %s" % ("match the filter" if pf.active else "found", args.pcap))

    who = None
    if args.whois:
        ranked = sorted(public_ips(set(a.ip_tx_b) | set(a.ip_rx_b)),
                        key=lambda ip: -(a.ip_tx_b[ip] + a.ip_rx_b[ip]))[:1000]
        try:
            who = cymru_whois(ranked)
        except OSError as e:
            print("warning: whois lookup failed (%s); continuing without it" % e, file=sys.stderr)
    traces = None if args.no_trace else build_traces(args.pcap, a, pf_kwargs, pick_flows(a), args.pcap)
    rep = build_report(a, args.pcap, max(1, args.top), who, traces, pf.describe() if pf.active else None)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fo:
            fo.write(rep.to_html())
        print("HTML report written to %s" % args.html, file=sys.stderr)
    tty = sys.stdout.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
    color = args.color == "always" or (args.color == "auto" and tty)
    width = max(80, min(150, shutil.get_terminal_size((100, 24)).columns)) if sys.stdout.isatty() else 130
    if args.json:
        text = json.dumps(rep.to_json(), indent=2, default=str) + "\n"
        shown = text
    else:
        text = rep.to_text(Style(False), width)
        shown = rep.to_text(Style(True), width) if color else text
    if not (args.quiet and (args.html or args.output or args.extract)):
        sys.stdout.write(shown)
    if args.output:
        with open(args.output, "w") as fo:
            fo.write(text)


if __name__ == "__main__":
    main()
