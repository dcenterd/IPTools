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

Usage: pcap_analyzer.py capture.pcap [--top N] [--json] [-o report.txt]
"""
import argparse
import gzip
import html
import ipaddress
import json
import math
import os
import random
import re
import shutil
import socket
import struct
import sys
import textwrap
from collections import Counter, defaultdict
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


# ------------------------------------------------------------------ analyzer

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
        self.flows = {}                          # key -> [pkts, bytes, first, last, proto]
        self.tcp_state = {}                      # key -> [syn, synack, rst, fin, established]
        self.next_seq = {}
        self.retrans = 0
        self.out_of_order = 0
        self.seen_seq = set()
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
        self.ntp = 0

    # ---- top level
    def add(self, ts, caplen, origlen, link, data):
        self.pkts += 1
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
        self.mac_pkts[mac_str(src)] += 1
        self.mac_bytes[mac_str(src)] += origlen
        if dst == b"\xff" * 6:
            self.cast["broadcast"] += 1
        elif dst[0] & 1:
            self.cast["multicast"] += 1
        else:
            self.cast["unicast"] += 1
        off = 14
        while et in (0x8100, 0x88A8, 0x9100) and len(data) >= off + 4:
            tci, et = struct.unpack("!HH", data[off:off + 4])
            self.vlans[tci & 0x0FFF] += 1
            stack.append("vlan")
            off += 4
        if et <= 1500:                     # 802.3 length field (LLC): STP/CDP/etc.
            self.ethertype["802.3/LLC"] += 1
            stack.append("llc")
            return
        self.decode_ethertype(et, data[off:], origlen, stack)

    def decode_ethertype(self, et, payload, origlen, stack):
        self.ethertype[ETHERTYPES.get(et, "0x%04x" % et)] += 1
        if et == 0x0800:
            self.decode_ipv4(payload, origlen, stack)
        elif et == 0x86DD:
            self.decode_ipv6(payload, origlen, stack)
        elif et == 0x0806:
            self.decode_arp(payload, stack)
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
        if spa != "0.0.0.0":
            self.arp_map[spa].add(sha)
        if spa == tpa:
            self.arp_gratuitous += 1

    # ---- L3
    def count_ip(self, src, dst, length, ver, stack):
        self._pair = (src, dst)
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
        if (ff & 0x1FFF) != 0 or (ff & 0x2000):
            self.frags += 1
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
        elif proto == 58 and len(p) >= 2:
            stack.append("icmpv6")
            self.l4["ICMPv6"] += 1
            self.icmp["%s (type %d)" % (ICMP6_TYPES.get(p[0], "other"), p[0])] += 1
        else:
            name = IPPROTOS.get(proto, "proto %d" % proto)
            stack.append(name.lower())
            self.l4[name] += 1

    def flow_update(self, key, origlen, ts_unused, proto):
        f = self.flows.get(key)
        if f is None:
            f = self.flows[key] = [0, 0, proto]
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
        payload = p[hl:]
        self.tcp_flags[flags_str(flags)] += 1
        a, b = (src, sport), (dst, dport)
        key = (a, b) if a <= b else (b, a)
        self.flow_update(key, origlen, None, "tcp")
        st = self.tcp_state.get(key)
        if st is None:
            st = self.tcp_state[key] = [0, 0, 0, 0, 0]
        syn, ackf = flags & 0x02, flags & 0x10
        if syn and not ackf:
            st[0] += 1
            self.syn_targets[src].add((dst, dport))
            self.tcp_dport[dport] += 1
            self.ip_services[dst]["%d/tcp" % dport] += 1
            self.tcp_dport_b[dport] += origlen
        elif syn and ackf:
            st[1] += 1
            self.answered.add((dst, src, sport))
        if flags & 0x04:
            st[2] += 1
            self.rst += 1
        if flags & 0x01:
            st[3] += 1
        if st[0] and st[1] and ackf and not syn:
            st[4] = 1
        if win == 0 and not (flags & 0x04) and not syn:
            self.zero_win += 1
        # retransmission heuristic: payload (or SYN/FIN) re-sent below the highest seq already seen
        dkey = (src, sport, dst, dport)
        seg = len(payload) + (1 if flags & 0x03 else 0)
        if seg:
            nxt = self.next_seq.get(dkey)
            if nxt is not None and ((seq - nxt) & 0xFFFFFFFF) > 0x80000000:
                if (dkey, seq) in self.seen_seq:
                    self.retrans += 1          # same segment start seen before: real retransmission
                else:
                    self.out_of_order += 1     # fills a gap: reordered, not re-sent
            elif len(self.seen_seq) < 2000000:
                self.seen_seq.add((dkey, seq))
            end = (seq + seg) & 0xFFFFFFFF
            if nxt is None or ((end - nxt) & 0xFFFFFFFF) < 0x80000000:
                self.next_seq[dkey] = end
        if payload:
            self.tcp_payload_pkts += 1
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
        self.flow_update(key, origlen, None, "udp")
        self.udp_dport[dport] += 1
        if dport in SERVICES or dport < 1024:
            self.ip_services[dst]["%d/udp" % dport] += 1
        self.udp_dport_b[dport] += origlen
        payload = p[8:]
        if payload:
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
                self.cleartext_hosts["FTP login"].add(src if dport == 21 else dst)
            elif text[:3].isdigit():
                self.banners["FTP: " + printable(text.split(b"\r")[0], 60)] += 1
        elif name == "telnet":
            stack.append("telnet")
            self.cleartext["Telnet session"] += 1
            self.cleartext_hosts["Telnet session"].add(dst if dport == 23 else src)
        elif name in ("smtp", "submission"):
            stack.append("smtp")
            if text[:3] == b"220":
                self.banners["SMTP: " + printable(text.split(b"\r")[0], 60)] += 1
            if text.upper().startswith((b"AUTH PLAIN", b"AUTH LOGIN")):
                self.cleartext["SMTP AUTH"] += 1
                self.cleartext_hosts["SMTP AUTH"].add(dst)
        elif name in ("pop3", "imap"):
            stack.append(name)
            up = text.upper()
            if b"USER " in up[:12] or b"PASS " in up[:12] or b" LOGIN " in up[:30]:
                self.cleartext[name.upper() + " login"] += 1
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
        body = d[9:]
        ver = struct.unpack("!H", body[0:2])[0]
        off = 34                                   # version + random
        sid = body[off]
        off += 1 + sid
        sel = None
        sni = None
        if hs == 1:
            self.tls_clienthello += 1
            cs = struct.unpack("!H", body[off:off + 2])[0]
            off += 2 + cs
            off += 1 + body[off]                   # compression methods
            vers = []
        else:
            self.tls_serverhello += 1
            sel = struct.unpack("!H", body[off:off + 2])[0]
            self.tls_ciphers["0x%04x" % sel] += 1
            off += 3                               # cipher + compression
        if off + 2 <= len(body):
            elen = struct.unpack("!H", body[off:off + 2])[0]
            off += 2
            end = min(len(body), off + elen)
            while off + 4 <= end:
                et, el = struct.unpack("!HH", body[off:off + 4])
                ed = body[off + 4:off + 4 + el]
                off += 4 + el
                if et == 0 and hs == 1 and len(ed) >= 5:
                    sni = ed[5:5 + struct.unpack("!H", ed[3:5])[0]].decode("latin-1")
                elif et == 0x10 and hs == 1 and len(ed) >= 3:
                    i = 2
                    while i < len(ed):
                        n = ed[i]
                        self.tls_alpn[ed[i + 1:i + 1 + n].decode("latin-1")] += 1
                        i += 1 + n
                elif et == 0x2B:
                    if hs == 1 and ed:
                        vers = [struct.unpack("!H", ed[i:i + 2])[0] for i in range(1, len(ed) - 1, 2)]
                        vers = [v for v in vers if v in TLS_VERSIONS]
                        if vers:
                            ver = max(vers)
                    elif hs == 2 and len(ed) >= 2:
                        ver = struct.unpack("!H", ed[:2])[0]
        label = TLS_VERSIONS.get(ver, "0x%04x" % ver)
        self.tls_hello_versions[("ClientHello offers up to " if hs == 1 else "ServerHello selects ") + label] += 1
        if label in ("SSLv3", "TLS 1.0", "TLS 1.1"):
            self.tls_old[("client offers at most " if hs == 1 else "server selected ") + label] += 1
        if sni:
            self.tls_sni[sni] += 1
            self.ip_sni[dst][sni] += 1

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
            if len(parts) >= 2 and parts[1].isdigit():
                self.http_status[parts[1].decode()] += 1
            if b"server" in hdrs:
                self.http_server[printable(hdrs[b"server"], 60)] += 1
            if b"content-type" in hdrs:
                self.http_ctype[printable(hdrs[b"content-type"].split(b";")[0], 40)] += 1
        else:
            self.http_methods[first.split(b" ")[0].decode("latin-1")] += 1
            if b"host" in hdrs:
                self.http_hosts[printable(hdrs[b"host"], 60)] += 1
                self.ip_http[dst][printable(hdrs[b"host"], 60)] += 1
            if b"user-agent" in hdrs:
                self.http_ua[printable(hdrs[b"user-agent"], 70)] += 1
            if b"authorization" in hdrs:
                self.http_auth += 1
                if hdrs[b"authorization"].lower().startswith(b"basic"):
                    self.cleartext["HTTP Basic auth"] += 1
                    self.cleartext_hosts["HTTP Basic auth"].add(dst)
            if first.startswith(b"POST ") and (b"password" in d.lower() or b"passwd" in d.lower()):
                self.cleartext["HTTP POST with password field"] += 1
                self.cleartext_hosts["HTTP POST with password field"].add(dst)

    # ---- L5-L7 over UDP
    def decode_udp_payload(self, src, dst, sport, dport, d, stack):
        ports = (sport, dport)
        if 53 in ports or 5353 in ports or 5355 in ports:
            self.decode_dns(src, dst, d, stack, mdns=(5353 in ports))
        elif 67 in ports or 68 in ports:
            self.decode_dhcp(d, stack)
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
        qname = None
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
        if qr:
            self.dns_responses += 1
            self.dns_rcode[DNS_RCODES.get(rcode, "rcode %d" % rcode)] += 1
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

    def decode_dhcp(self, d, stack):
        stack.append("dhcp")
        if len(d) < 240 or d[236:240] != b"\x63\x82\x53\x63":
            return
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
                self.dhcp_types[DHCP_TYPES.get(val[0], str(val[0]))] += 1
            elif code == 12:
                self.dhcp_hosts[printable(val, 40)] += 1
            elif code == 60:
                self.dhcp_vendor[printable(val, 40)] += 1
            off += 2 + ln


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
    bins = [0] * n
    for sec, b in per_second.items():
        bins[min(n - 1, int((sec - lo) * n / span))] += b
    return bins, lo, hi + 1, span / n


_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}


def sort_key(cell):
    """Numeric value of a table cell ('1,234', '12.5%', '1.4 MB') or None."""
    m = re.fullmatch(r"(-?\d+(?:\.\d+)?)\s*(%|[KMGT]?B)?", cell.replace(",", "").strip())
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
        sec["items"].append({"t": "findings", "items": sorted(items, key=lambda x: SEVERITY[x[0]][2])})

    @staticmethod
    def timeline(sec, per_second):
        if per_second:
            sec["items"].append({"t": "timeline", "per_second": per_second})

    @staticmethod
    def donut(sec, title, pairs):
        if pairs:
            sec["items"].append({"t": "donut", "title": title, "pairs": pairs})

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
        return "\n".join(out).lstrip("\n") + "\n"

    @staticmethod
    def _table_text(st, it, width):
        headers, rows = it["headers"], it["rows"]
        bi = bar_col(headers)
        cols = list(zip(*([headers] + rows)))
        widths = [min(max(len(c) for c in col), 58) for col in cols]
        budget = width - 6 - (14 if bi is not None else 0) - 2 * (len(widths) - 1)
        while sum(widths) > budget and max(widths) > 16:
            widths[widths.index(max(widths))] -= 1
        right = [all(_numlike(r[i]) for r in rows) for i in range(len(headers))]

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
        for sev, text in items:
            label, style, _ = SEVERITY[sev]
            lines = textwrap.wrap(text, max(30, width - 14)) or [""]
            out.append("  " + st(style, " %-6s " % label) + " " + lines[0])
            out += ["  " + " " * 9 + " " + l for l in lines[1:]]
        return out

    @staticmethod
    def _timeline_text(st, per_second, width):
        n = max(20, min(80, width - 20))
        bins, lo, hi, bs = bin_series(per_second, n)
        rows = tall_chart(bins, 4)
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
                    sec["findings"] = [{"severity": a, "text": b} for a, b in it["items"]]
                elif t == "timeline":
                    bins, lo, hi, bs = bin_series(it["per_second"], 60)
                    sec["timeline"] = {"start": lo, "end": hi, "seconds_per_bin": bs, "bytes": bins}
                elif t == "hosts":
                    sec["hosts"] = it["hosts"]
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
.wrap{max-width:1180px;margin:0 auto;padding:0 16px}
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
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi .l{font-size:12px;color:var(--mute);text-transform:uppercase;letter-spacing:.5px}
.kpi .v{font-size:24px;font-weight:650;font-variant-numeric:tabular-nums;margin:2px 0}
.kpi .s{font-size:12px;color:var(--mute)}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:18px}
section h2{margin:0 0 12px;font-size:16px;letter-spacing:.3px}
h3{margin:0 0 8px;font-size:13px;color:var(--mute);font-weight:600}
dl.kv{display:grid;grid-template-columns:minmax(180px,max-content) 1fr;gap:4px 18px;margin:0 0 12px}
dl.kv dt{color:var(--mute)}dl.kv dd{margin:0;font-variant-numeric:tabular-nums;word-break:break-word}
p.note{color:var(--mute);margin:6px 0;font-size:13px}
.tables{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,430px),1fr));gap:14px;margin-top:6px}
.tcard{border:1px solid var(--line);border-radius:10px;padding:10px 12px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:4px 8px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
tr:last-child td{border-bottom:0}
th{color:var(--mute);font-weight:600;cursor:pointer;user-select:none}
th:hover{color:var(--ink)}th.asc::after{content:" \\25B2"}th.desc::after{content:" \\25BC"}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td.txt{max-width:340px;overflow:hidden;text-overflow:ellipsis}
.bar{position:relative;min-width:96px;height:18px;line-height:18px}
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
@media print{nav,.theme{display:none}body{background:#fff}section{break-inside:avoid}}
"""

HTML_JS = """
(function(){var r=document.documentElement,b=document.querySelector('.theme');
if(b)b.onclick=function(){var d=r.getAttribute('data-theme')==='dark'||(!r.getAttribute('data-theme')&&matchMedia('(prefers-color-scheme: dark)').matches);r.setAttribute('data-theme',d?'light':'dark')};
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
    return title.title()


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


def linkify_cell(text):
    """Table cells: 'ip', 'ip  (name)', 'ip:port' or '[v6]:port' - link the address part only."""
    m = re.match(r"^\[?([0-9a-fA-F:.]+)\]?(?=$|:\d+$|\s)", text)
    if m and m.group(1) in LINKABLE:
        s, e = m.span(1)
        return _e(text[:s]) + '<a class="ip" href="#%s">%s</a>' % (host_id(m.group(1)), _e(m.group(1))) + _e(text[e:])
    return _e(text)


def _html_table(it):
    headers, rows = it["headers"], it["rows"]
    bi = bar_col(headers)
    num = [all(_numlike(r[i]) for r in rows) for i in range(len(headers))]
    out = ['<div class="tcard"><h3>%s</h3><table class="sortable"><thead><tr>' % _e(it["title"])]
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
                out.append('<td class="%s"%s title="%s">%s</td>' % ("num" if num[i] else "txt", dv, _e(c), linkify_cell(c)))
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def _svg_timeline(per_second):
    n = 120
    bins, lo, hi, bs = bin_series(per_second, n)
    rates = [b * 8 / bs for b in bins]
    mx = max(rates) or 1
    W, H, L, B, T, Rr = 900, 210, 70, 28, 10, 10
    pw, ph = W - L - Rr, H - T - B
    bw = pw / n
    out = ['<svg class="chart" viewBox="0 0 %d %d" role="img" aria-label="Traffic over time">' % (W, H)]
    for k in range(5):
        y = T + ph - ph * k / 4
        out.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="var(--line)"/>' % (L, W - Rr, y, y))
        out.append('<text x="%d" y="%.1f" text-anchor="end">%s</text>' % (L - 6, y + 4, _e(human_bps(mx * k / 4) if k else "0")))
    for i, r in enumerate(rates):
        if r <= 0:
            continue
        h = max(1.0, ph * r / mx)
        t0 = fmt_ts(lo + i * bs)[11:19]
        out.append('<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="var(--c1)" rx="1"><title>%s UTC - %s</title></rect>'
                   % (L + i * bw, T + ph - h, max(1.0, bw - 1), h, _e(t0), _e(human_bps(r))))
    for frac, anchor in ((0, "start"), (0.5, "middle"), (1, "end")):
        x = L + pw * frac
        out.append('<text x="%.1f" y="%d" text-anchor="%s">%s</text>' % (x, H - 8, anchor, _e(fmt_ts(lo + (hi - lo) * frac)[11:19] + " UTC")))
    out.append("</svg>")
    return "".join(out)


def _svg_donut(title, pairs):
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
        segs.append('<circle r="%d" cx="75" cy="75" fill="none" stroke="%s" stroke-width="%d" stroke-dasharray="%.2f %.2f" '
                    'stroke-dashoffset="%.2f" transform="rotate(-90 75 75)"><title>%s: %s (%.1f%%)</title></circle>'
                    % (r, col, sw, max(0.0, ln - 1.0), circ - max(0.0, ln - 1.0), -cum, _e(lab), "{:,}".format(v), 100.0 * v / total))
        legend.append('<li><b style="background:%s"></b>%s<em>%.1f%%</em></li>' % (col, _e(lab), 100.0 * v / total))
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
    finds = "".join('<div class="finding"><span class="badge %s">%s</span><span>%s</span></div>' % (
        sev, SEVERITY[sev][0], linkify(text)) for sev, text in h["findings"])
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
    parts.append('<header class="top"><div class="wrap"><button class="theme" type="button">Theme</button>'
                 '<h1>Packet capture report</h1><div class="sub">%s &middot; %s &middot; generated %s</div></div></header>'
                 % (_e(meta.get("path", "")), _e(meta.get("format", "")), _e(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))))
    nav = [("findings", "Findings")] + [(_slug(s["title"]), _nav_label(s["title"])) for s in rep.sections
                                          if not all(it["t"] in ("kpis", "findings") for it in s["items"])]
    parts.append('<nav><div class="wrap">%s</div></nav>' % "".join(
        '<a href="#%s">%s</a>' % (h, _e(l)) for h, l in nav))
    parts.append('<main class="wrap">')
    for s in rep.sections:
        for it in s["items"]:
            if it["t"] == "kpis":
                parts.append('<div class="kpis">%s</div>' % "".join(
                    '<div class="kpi"><div class="l">%s</div><div class="v">%s</div><div class="s">%s</div></div>'
                    % (_e(l), _e(v), _e(sub)) for l, v, sub in it["items"]))
            elif it["t"] == "findings":
                body = ('<div class="finding"><span class="ok">&#10004;</span><span>Nothing notable found by the built-in checks.</span></div>'
                        if not it["items"] else "".join(
                            '<div class="finding"><span class="badge %s">%s</span><span>%s</span></div>'
                            % (sev, SEVERITY[sev][0], linkify(text)) for sev, text in it["items"]))
                parts.append('<section id="findings"><h2>Findings <span class="note" style="font-weight:400;color:var(--mute)">'
                             '(heuristics - verify before acting)</span></h2><div class="findings">%s</div></section>' % body)
    for s in rep.sections:
        if all(it["t"] in ("kpis", "findings") for it in s["items"]):
            continue
        parts.append('<section id="%s"><h2>%s</h2>' % (_slug(s["title"]), _e(s["title"])))

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
                    ds.append(_svg_donut(items[i]["title"], items[i]["pairs"]))
                    i += 1
                parts.append('<div class="donuts">%s</div>' % "".join(ds))
                continue
            if t == "hosts":
                parts.append('<p class="note">Click an IP anywhere in this report to jump to its card.</p>'
                             '<div class="hostlist">%s</div>' % "".join(_host_card(h) for h in it["hosts"]))
            elif t == "note":
                if not it.get("text_only"):
                    parts.append('<p class="note">%s</p>' % _e(it["text"]))
            elif t == "timeline":
                parts.append("<h3>Traffic over time (bandwidth)</h3>" + _svg_timeline(it["per_second"]))
            elif t == "graph":
                parts.append("<h3>Conversation map (top hosts)</h3>" + _svg_graph(it))
            i += 1
        parts.append("</section>")
    parts.append("</main><script>%s</script></body></html>" % HTML_JS)
    return "".join(parts)


def pct(n, total):
    return "%.1f%%" % (100.0 * n / total) if total else "-"


def top(counter, n, total=None, label=None):
    rows = []
    total = total if total is not None else sum(counter.values())
    for k, v in counter.most_common(n):
        rows.append((label(k) if label else k, "{:,}".format(v), pct(v, total)))
    return rows


def build_report(a, path, topn, whois=None):
    W = whois or {}
    R = Report()
    m = a.meta
    R.meta = {"path": path, "format": m.get("format", "?")}
    dur = (a.last_ts - a.first_ts) if a.first_ts is not None else 0
    ips = set(a.ip_tx_p) | set(a.ip_rx_p)
    obs = observations(a, dur)
    nhigh = sum(1 for o in obs if o[0] == "high")
    nmed = sum(1 for o in obs if o[0] == "medium")

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
        R.timeline(s, a.per_second)
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
        R.table(s, "Top networks / organisations (whois, by bytes)", ["Network", "IPs", "Packets", "Bytes", "% of traffic"],
                [(k, len(v[2]), "{:,}".format(v[1]), human_bytes(v[0]), pct(v[0], sum(tb.values())))
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
    est = sum(1 for st in a.tcp_state.values() if st[4])
    syn_only = sum(1 for st in a.tcp_state.values() if st[0] and not st[1])
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

    # ---- L5/6
    s = R.section("LAYER 5-6 - SESSION / PRESENTATION (TLS)")
    R.kv(s, "ClientHello / ServerHello", "{:,} / {:,}".format(a.tls_clienthello, a.tls_serverhello))
    R.table(s, "Negotiated / offered versions", ["Handshake", "Count", "%"], top(a.tls_hello_versions, 8))
    R.table(s, "TLS record versions", ["Version", "Records", "%"], top(a.tls_versions, 6))
    R.table(s, "Server names (SNI)", ["SNI", "Hellos", "%"], top(a.tls_sni, topn))
    R.table(s, "ALPN protocols offered", ["ALPN", "Count", "%"], top(a.tls_alpn, 6))
    R.table(s, "Server-selected cipher suites (IANA id)", ["Cipher", "Count", "%"], top(a.tls_ciphers, 6))
    R.table(s, "Other TLS records", ["Type", "Records", "%"], top(a.tls_records, 6))
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
            "findings": [o for o in obs if mention.search(o[1])],
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


def observations(a, dur):
    """Heuristic findings as (severity, text); severity is high / medium / info."""
    out = []
    for src, targets in a.syn_targets.items():
        unanswered = [t for t in targets if (src, t[0], t[1]) not in a.answered]
        hosts = {t[0] for t in unanswered}
        ports = {t[1] for t in unanswered}
        if len(unanswered) >= 20 and len(unanswered) >= 0.8 * len(targets):
            kind = "port scan" if len(ports) > len(hosts) else "host sweep"
            out.append(("high", "Possible TCP %s from %s: %d unanswered SYNs to %d host(s) / %d port(s)." % (
                kind, src, len(unanswered), len(hosts), len(ports))))
    tcp_pk = a.l4.get("TCP", 0)
    if tcp_pk > 100 and a.retrans / tcp_pk > 0.02:
        out.append(("medium", "High TCP retransmission rate: %s of TCP packets (possible loss/congestion)." % pct(a.retrans, tcp_pk)))
    if tcp_pk > 100 and a.rst / tcp_pk > 0.05:
        out.append(("medium", "Many TCP resets: %s of TCP packets (refused ports, aborted sessions or a scan)." % pct(a.rst, tcp_pk)))
    if a.zero_win:
        out.append(("medium", "%d zero-window packets: a receiver could not keep up." % a.zero_win))
    for what, n in a.cleartext.items():
        hosts = ", ".join(sorted(a.cleartext_hosts[what])[:5])
        out.append(("high", "Cleartext traffic: %s (%d packets) to/from %s - credentials/data may be readable." % (what, n, hosts)))
    for what, n in a.tls_old.items():
        out.append(("medium", "Deprecated TLS: %d handshake(s) where the %s." % (n, what)))
    nx = a.dns_rcode.get("NXDOMAIN", 0)
    if a.dns_responses >= 20 and nx / a.dns_responses > 0.3:
        out.append(("medium", "%s of DNS responses are NXDOMAIN (possible DGA/malware or misconfiguration)." % pct(nx, a.dns_responses)))
    if len(a.dns_long) >= 5:
        out.append(("medium", "%d DNS queries with very long names (e.g. %s) - check for DNS tunnelling." % (len(a.dns_long), a.dns_long[0][:60])))
    if a.dns_qtype.get("TXT", 0) > 20 or a.dns_qtype.get("ANY", 0) > 5:
        out.append(("info", "Unusual DNS types: TXT=%d ANY=%d." % (a.dns_qtype.get("TXT", 0), a.dns_qtype.get("ANY", 0))))
    for ip, macs in a.arp_map.items():
        if len(macs) > 1:
            out.append(("high", "ARP: %s claimed by %d different MACs (%s) - conflict or ARP spoofing." % (ip, len(macs), ", ".join(sorted(macs)))))
    if a.arp_gratuitous > 5:
        out.append(("info", "%d gratuitous ARP packets." % a.arp_gratuitous))
    echo = a.icmp.get("echo-request (type 8 code 0)", 0)
    if echo > 100 and dur > 0 and echo / dur > 50:
        out.append(("medium", "ICMP echo-request rate %.0f/s (ping flood or sweep)." % (echo / dur)))
    if a.udp_port_unreach > 20:
        out.append(("info", "%d ICMP port-unreachable messages (UDP to closed ports, possible UDP scan)." % a.udp_port_unreach))
    if a.frags > 0:
        out.append(("info", "%d fragmented IP packets (check MTU issues or evasion)." % a.frags))
    if a.truncated:
        out.append(("info", "%d packets are truncated by the snap length; payload analysis is incomplete for them." % a.truncated))
    if a.malformed:
        out.append(("info", "Malformed packets: " + ", ".join("%s (%d)" % kv for kv in a.malformed.items()) + "."))
    return out


# ------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description="Analyze a pcap/pcapng capture and print a text report "
                                 "(top IPs, protocols, layers 1-7, findings), optionally as an HTML report.")
    ap.add_argument("pcap", help="capture file (.pcap, .pcapng, optionally .gz)")
    ap.add_argument("-n", "--top", type=int, default=10, help="rows per top-list (default 10)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report with charts")
    ap.add_argument("-q", "--quiet", action="store_true", help="with --html/-o: do not print the report to the terminal")
    ap.add_argument("-o", "--output", help="write the plain-text report to this file as well")
    ap.add_argument("--whois", action="store_true",
                    help="look up ASN/organisation/country of the public IPs (sends them to whois.cymru.com)")
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                    help="colors in terminal output (default auto; NO_COLOR is respected)")
    args = ap.parse_args()

    a = Analyzer()
    try:
        fh = open_capture(args.pcap)
    except OSError as e:
        sys.exit("error: %s" % e)
    try:
        with fh:
            for pkt in iter_packets(fh, a.meta):
                a.add(*pkt)
    except CaptureError as e:
        sys.exit("error: %s" % e)
    except (EOFError, OSError) as e:
        a.meta["warning"] = "read error: %s" % e
    if a.pkts == 0:
        sys.exit("error: no packets found in %s" % args.pcap)

    who = None
    if args.whois:
        ranked = sorted(public_ips(set(a.ip_tx_b) | set(a.ip_rx_b)),
                        key=lambda ip: -(a.ip_tx_b[ip] + a.ip_rx_b[ip]))[:1000]
        try:
            who = cymru_whois(ranked)
        except OSError as e:
            print("warning: whois lookup failed (%s); continuing without it" % e, file=sys.stderr)
    rep = build_report(a, args.pcap, max(1, args.top), who)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(rep.to_html())
        print("HTML report written to %s" % args.html, file=sys.stderr)
    tty = sys.stdout.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
    color = args.color == "always" or (args.color == "auto" and tty)
    width = max(80, min(120, shutil.get_terminal_size((100, 24)).columns)) if sys.stdout.isatty() else 100
    if args.json:
        text = json.dumps(rep.to_json(), indent=2, default=str) + "\n"
        shown = text
    else:
        text = rep.to_text(Style(False), width)
        shown = rep.to_text(Style(True), width) if color else text
    if not (args.quiet and (args.html or args.output)):
        sys.stdout.write(shown)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)


if __name__ == "__main__":
    main()
