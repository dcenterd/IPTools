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
import ipaddress
import json
import math
import socket
import struct
import sys
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
        try:
            self.decode_link(link, data, origlen, stack)
        except (struct.error, IndexError, ValueError):
            self.malformed["truncated/malformed packet"] += 1
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


# ------------------------------------------------------------------ report model

class Report:
    """Collects sections once; rendered as text or JSON."""

    def __init__(self):
        self.sections = []

    def section(self, title):
        s = {"title": title, "items": []}
        self.sections.append(s)
        return s

    @staticmethod
    def kv(sec, key, value):
        sec["items"].append(("kv", key, value))

    @staticmethod
    def note(sec, text):
        sec["items"].append(("note", text))

    @staticmethod
    def table(sec, title, headers, rows):
        if rows:
            sec["items"].append(("table", title, headers, rows))

    def to_text(self, width=100):
        out = []
        for s in self.sections:
            out.append("")
            out.append("=" * 8 + " " + s["title"] + " " + "=" * max(3, width - len(s["title"]) - 10))
            kvs = [i for i in s["items"] if i[0] == "kv"]
            kw = max((len(i[1]) for i in kvs), default=0)
            for it in s["items"]:
                if it[0] == "kv":
                    out.append("  %-*s  %s" % (kw, it[1], it[2]))
                elif it[0] == "note":
                    out.append("  " + it[1])
                else:
                    _, title, headers, rows = it
                    out.append("")
                    out.append("  " + title)
                    cols = list(zip(*([headers] + [[str(c) for c in r] for r in rows])))
                    widths = [min(max(len(str(c)) for c in col), 58) for col in cols]
                    right = [all(_numlike(str(r[i])) for r in rows) for i in range(len(headers))]

                    def line(cells):
                        parts = []
                        for i, c in enumerate(cells):
                            c = str(c)
                            if len(c) > widths[i]:
                                c = c[:widths[i] - 1] + "…"
                            parts.append(c.rjust(widths[i]) if right[i] else c.ljust(widths[i]))
                        return "    " + "  ".join(parts).rstrip()
                    out.append(line(headers))
                    out.append("    " + "  ".join("-" * w for w in widths))
                    for r in rows:
                        out.append(line(r))
        return "\n".join(out).lstrip("\n") + "\n"

    def to_json(self):
        data = {}
        for s in self.sections:
            sec = {"values": {}, "notes": [], "tables": {}}
            for it in s["items"]:
                if it[0] == "kv":
                    sec["values"][it[1]] = it[2]
                elif it[0] == "note":
                    sec["notes"].append(it[1])
                else:
                    _, title, headers, rows = it
                    sec["tables"][title] = [dict(zip(headers, r)) for r in rows]
            data[s["title"]] = sec
        return data


def _numlike(s):
    s = s.replace(",", "").replace("%", "").replace(".", "", 1).strip()
    return s.isdigit() or s in ("-", "")


def pct(n, total):
    return "%.1f%%" % (100.0 * n / total) if total else "-"


def top(counter, n, total=None, label=None):
    rows = []
    total = total if total is not None else sum(counter.values())
    for k, v in counter.most_common(n):
        rows.append((label(k) if label else k, "{:,}".format(v), pct(v, total)))
    return rows


def spark_series(per_second, width=60):
    if not per_second:
        return ""
    lo, hi = min(per_second), max(per_second)
    span = hi - lo + 1
    bins = [0] * width
    for sec, b in per_second.items():
        bins[min(width - 1, int((sec - lo) * width / span))] += b
    mx = max(bins) or 1
    return "".join(SPARKS[min(7, int(b / mx * 7.999))] if b else " " for b in bins)


def build_report(a, path, topn):
    R = Report()
    m = a.meta
    dur = (a.last_ts - a.first_ts) if a.first_ts is not None else 0

    # ---- summary
    s = R.section("SUMMARY")
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
    ips = set(a.ip_tx_p) | set(a.ip_rx_p)
    R.kv(s, "Unique IP addresses", "{:,}".format(len(ips)))
    R.kv(s, "Flows (TCP+UDP)", "{:,}".format(len(a.flows)))
    if m.get("warning"):
        R.kv(s, "Warning", m["warning"])
    if a.malformed:
        R.kv(s, "Malformed/truncated", ", ".join("%s: %d" % kv for kv in a.malformed.items()))

    # ---- protocol hierarchy
    s = R.section("PROTOCOL HIERARCHY (protocol stack per packet)")
    rows = [(k, "{:,}".format(v), pct(v, a.pkts), human_bytes(a.stack_bytes[k]))
            for k, v in a.stack_pkts.most_common(topn * 2)]
    R.table(s, "Stack", ["Protocols", "Packets", "%", "Bytes"], rows)

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
        R.kv(s, "Traffic over time", "|" + spark_series(a.per_second) + "|")
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

    def ip_rows(pk, by, n):
        rows = []
        for ip, v in by.most_common(n):
            rows.append((named(ip), ip_class(ip), "{:,}".format(pk[ip]), human_bytes(v), pct(v, a.bytes)))
        return rows
    R.table(s, "Top senders (by bytes)", ["IP", "Class", "Packets", "Bytes", "% of traffic"],
            ip_rows(a.ip_tx_p, a.ip_tx_b, topn))
    R.table(s, "Top receivers (by bytes)", ["IP", "Class", "Packets", "Bytes", "% of traffic"],
            ip_rows(a.ip_rx_p, a.ip_rx_b, topn))
    tot_ip = {ip: a.ip_tx_p[ip] + a.ip_rx_p[ip] for ip in ips}
    tb = {ip: a.ip_tx_b[ip] + a.ip_rx_b[ip] for ip in ips}
    R.table(s, "Most active IPs (sent + received)", ["IP", "Class", "Packets", "Bytes"],
            [(named(ip), ip_class(ip), "{:,}".format(tot_ip[ip]), human_bytes(v))
             for ip, v in sorted(tb.items(), key=lambda kv: -kv[1])[:topn]])
    R.table(s, "Top conversations (IP pairs, by bytes)", ["Host A", "Host B", "Packets", "Bytes"],
            [(x, y, "{:,}".format(a.conv_p[(x, y)]), human_bytes(v)) for (x, y), v in a.conv_b.most_common(topn)])
    cls = Counter()
    for ip in ips:
        cls[ip_class(ip)] += 1
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
    R.table(s, "Transport protocols", ["Protocol", "Packets", "%"], top(a.l4, 8))
    svc = lambda p: "%d  %s" % (p, SERVICES.get(p, ""))
    R.table(s, "Top TCP destination ports (SYNs = connection attempts)", ["Port", "SYNs", "%"],
            top(a.tcp_dport, topn, label=svc))
    R.table(s, "Top UDP destination ports (by packets)", ["Port", "Packets", "%"],
            top(a.udp_dport, topn, label=svc))
    R.table(s, "TCP flag combinations", ["Flags", "Packets", "%"], top(a.tcp_flags, topn))
    tcp_flows = [(k, v) for k, v in a.flows.items() if v[2] == "tcp"]
    udp_flows = [(k, v) for k, v in a.flows.items() if v[2] == "udp"]
    est = sum(1 for k, st in a.tcp_state.items() if st[4])
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
        rows = []
        for (x, y), v in sorted(flows, key=lambda kv: -kv[1][1])[:topn]:
            rows.append(("%s:%d" % x if ":" not in x[0] else "[%s]:%d" % x,
                         "%s:%d" % y if ":" not in y[0] else "[%s]:%d" % y,
                         "{:,}".format(v[0]), human_bytes(v[1])))
        return rows
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

    # ---- observations
    s = R.section("OBSERVATIONS (heuristics - verify before acting)")
    obs = observations(a, dur)
    if obs:
        for o in obs:
            R.note(s, "- " + o)
    else:
        R.note(s, "Nothing notable found by the built-in checks.")
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
    out = []
    for src, targets in a.syn_targets.items():
        unanswered = [t for t in targets if (src, t[0], t[1]) not in a.answered]
        hosts = {t[0] for t in unanswered}
        ports = {t[1] for t in unanswered}
        if len(unanswered) >= 20 and len(unanswered) >= 0.8 * len(targets):
            kind = "port scan" if len(ports) > len(hosts) else "host sweep"
            out.append("Possible TCP %s from %s: %d unanswered SYNs to %d host(s) / %d port(s)." % (
                kind, src, len(unanswered), len(hosts), len(ports)))
    tcp_pk = a.l4.get("TCP", 0)
    if tcp_pk > 100 and a.retrans / tcp_pk > 0.02:
        out.append("High TCP retransmission rate: %s of TCP packets (possible loss/congestion)." % pct(a.retrans, tcp_pk))
    if tcp_pk > 100 and a.rst / tcp_pk > 0.05:
        out.append("Many TCP resets: %s of TCP packets (refused ports, aborted sessions or a scan)." % pct(a.rst, tcp_pk))
    if a.zero_win:
        out.append("%d zero-window packets: a receiver could not keep up." % a.zero_win)
    for what, n in a.cleartext.items():
        hosts = ", ".join(sorted(a.cleartext_hosts[what])[:5])
        out.append("Cleartext traffic: %s (%d packets) to/from %s - credentials/data may be readable." % (what, n, hosts))
    for what, n in a.tls_old.items():
        out.append("Deprecated TLS: %d handshake(s) where the %s." % (n, what))
    nx = a.dns_rcode.get("NXDOMAIN", 0)
    if a.dns_responses >= 20 and nx / a.dns_responses > 0.3:
        out.append("%s of DNS responses are NXDOMAIN (possible DGA/malware or misconfiguration)." % pct(nx, a.dns_responses))
    if len(a.dns_long) >= 5:
        out.append("%d DNS queries with very long names (e.g. %s) - check for DNS tunnelling." % (len(a.dns_long), a.dns_long[0][:60]))
    if a.dns_qtype.get("TXT", 0) > 20 or a.dns_qtype.get("ANY", 0) > 5:
        out.append("Unusual DNS types: TXT=%d ANY=%d." % (a.dns_qtype.get("TXT", 0), a.dns_qtype.get("ANY", 0)))
    for ip, macs in a.arp_map.items():
        if len(macs) > 1:
            out.append("ARP: %s claimed by %d different MACs (%s) - conflict or ARP spoofing." % (ip, len(macs), ", ".join(sorted(macs))))
    if a.arp_gratuitous > 5:
        out.append("%d gratuitous ARP packets." % a.arp_gratuitous)
    echo = a.icmp.get("echo-request (type 8 code 0)", 0)
    if echo > 100 and dur > 0 and echo / dur > 50:
        out.append("ICMP echo-request rate %.0f/s (ping flood or sweep)." % (echo / dur))
    if a.udp_port_unreach > 20:
        out.append("%d ICMP port-unreachable messages (UDP to closed ports, possible UDP scan)." % a.udp_port_unreach)
    if a.frags > 0:
        out.append("%d fragmented IP packets (check MTU issues or evasion)." % a.frags)
    if a.truncated:
        out.append("%d packets are truncated by the snap length; payload analysis is incomplete for them." % a.truncated)
    if a.malformed:
        out.append("Malformed packets: " + ", ".join("%s (%d)" % kv for kv in a.malformed.items()) + ".")
    return out


# ------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description="Analyze a pcap/pcapng capture and print a text report "
                                 "(top IPs, protocols, layers 1-7, observations).")
    ap.add_argument("pcap", help="capture file (.pcap, .pcapng, optionally .gz)")
    ap.add_argument("-n", "--top", type=int, default=10, help="rows per top-list (default 10)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("-o", "--output", help="write the report to this file as well")
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

    rep = build_report(a, args.pcap, max(1, args.top))
    text = json.dumps(rep.to_json(), indent=2, default=str) + "\n" if args.json else rep.to_text()
    sys.stdout.write(text)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)


if __name__ == "__main__":
    main()
