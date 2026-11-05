# IPTools

Small collection of Python network utilities for IP/ASN research and MikroTik address-list automation.

Most scripts query public data sources ([RIPEstat](https://stat.ripe.net), the RIPE Database and the RIR delegated statistics), so they need internet access but no API keys.

## Scripts

| Script | What it does |
|---|---|
| `iplookup.py` | Who is behind an IP (v4/v6)? Shows the announcing prefix and origin ASN, ASN holder, reverse DNS, and (with `--prefixes`) all prefixes of that ASN; `--json` for scripts. Falls back to the registry record if the IP is not in BGP. |
| `asn2prefix.py` | Given an AS number, prints owner info, a routing summary (prefix and address counts, neighbours) and every announced prefix. |
| `bgp-lg.py` | Looking glass: shows the BGP AS path towards an IP, draws it as a text topology and saves it as a PDF. |
| `prefix-history.py` | Routing history of a prefix or ASN: first/last seen, announced now or not, and the announcement periods. |
| `whois-contacts.py` | Who to contact about an IP, prefix or ASN: abuse contact plus admin/tech contacts with e-mail and phone. |
| `country2subnet.py` | Builds IPv4 prefix lists for one or more countries from the delegated statistics of all five RIRs. Writes plain lists and MikroTik `.rsc` files. |
| `mikrotik_subnet_updater.py` | Syncs a country's prefix list into a MikroTik firewall address-list through the RouterOS REST API (adds missing, removes stale, asks before changing anything). |
| `ripe_ip_checker.py` | Pre-purchase due-diligence report for IPv4 ranges in the RIPE region: ownership, transfers, routing history, RPKI/IRR, reputation, geolocation, past usage, compliance and fragmentation. |
| `ssl_checker.py` | Checks the SSL/TLS certificate of one or many websites: expiry, invalid/self-signed/wrong-host certificates, missing intermediate (incomplete chain) and DNS failures. Shows a table with issuer and days left, can alert by webhook or e-mail, run on a schedule in the background, and dump certificates as PEM plus decoded text. |
| `cve_checker.py` | Latest published CVEs from NVD and CIRCL, ranked by real-world risk: CISA KEV (exploited now) first, then EPSS exploitation probability, then CVSS score. Filter by days, keyword, severity or score; table or JSON output. |
| `ipx.py` | All-in-one network diagnostics (Linux, no root needed): traceroute over ICMP, UDP or TCP, with per-hop ASN/org/country (`--asn`), path MTU discovery (`--mtu`), protocol/host comparison (`--compare`), live per-hop stats with sparklines (`--live`), ping with stats (`--ping`) and TCP/UDP port scan (`--scan`, `--open`). Uses only the standard library. A single-binary Go port lives in [`ipx-go/`](ipx-go/) (prebuilt Linux amd64/arm64 on the [Releases](https://github.com/dcenterd/IPTools/releases) page). |
| `pcap_analyzer.py` | Packet-capture debugger (`.pcap`, `.pcapng`, `.gz`; standard library only). Text dashboard or `--html` report with charts, a conversation map and clickable per-host cards; `--json`. Covers layers 1-7 plus: **expert findings with packet numbers and ready-to-paste Wireshark filters**; per-flow TCP health (handshake/RTT, retransmissions, dup-ACKs, zero-window, resets) with ladder diagrams, throughput and sequence graphs; latency tables (TCP handshake, DNS, TLS, HTTP); path/MTU checks (MSS, ICMP fragmentation-needed, PMTU black holes); L2 discovery (LLDP/CDP neighbours, STP changes, DHCP problems, ARP sweeps/storms, duplicate IPs, broadcast storms); TLS certificates (expiry, self-signed, weak key/signature, name mismatch), JA3 fingerprints and beaconing detection; `--whois` for ASN/org/country. Filters (`--host --port --proto --flow --from --to`) narrow the analysis and `--extract` writes the selection to a new pcap. |

## Requirements

- Python 3.8+
- `requests` (all scripts except `ripe_ip_checker.py`, `ssl_checker.py`, `cve_checker.py` and `pcap_analyzer.py`, which use only the standard library)

```sh
git clone https://github.com/dcenterd/IPTools.git
cd IPTools
pip install -r requirements.txt
```

## Usage

```sh
# who is behind this IP?
./iplookup.py                     # prompts for the IP
./iplookup.py 8.8.8.8 --prefixes  # also list every IPv4 prefix of the ASN
./iplookup.py 8.8.8.8 --json      # machine-readable output

# everything about an AS
./asn2prefix.py                   # prompts for the AS number (e.g. AS15169)

# BGP path towards an IP (also writes bgp_path_<ip>.pdf)
./bgp-lg.py 8.8.8.8

# routing history of a prefix or ASN
./prefix-history.py 193.0.0.0/21
./prefix-history.py AS3333 --all

# abuse / admin / tech contacts
./whois-contacts.py 193.0.0.1
./whois-contacts.py AS3333

# prefix lists per country (2-letter ISO codes, GB for the UK)
./country2subnet.py IR AM TR
./country2subnet.py --refresh DE  # ignore cached downloads

# IP range due diligence
./ripe_ip_checker.py 193.0.0.0/21 --output-dir reports

# SSL certificate check (one or many sites)
./ssl_checker.py github.com example.org:8443
./ssl_checker.py -f sites.txt --warn-days 30 --dump-cert certs
./ssl_checker.py -f sites.txt --every 6h --background --webhook <url>

# analyze a capture (top IPs, protocols, layers 1-7, findings)
./pcap_analyzer.py capture.pcap -n 15 -o report.txt
./pcap_analyzer.py capture.pcap --html report.html -q   # shareable HTML report only
./pcap_analyzer.py capture.pcap --whois                # + who owns the IPs (ASN/org/country)
./pcap_analyzer.py capture.pcap --host 10.0.0.5 --port 443 --from +30 --to +90   # narrow the analysis
./pcap_analyzer.py capture.pcap --flow 10.0.0.5:40000,93.184.216.34:80 --extract flow.pcap   # cut one conversation for Wireshark

# newest CVEs, riskiest first
./cve_checker.py --days 7 --severity high
./cve_checker.py --keyword "PHP before" --days 30
./cve_checker.py --kev                     # only actively exploited

# traceroute / ping / MTU / port scan (Linux, no root)
./ipx.py 8.8.8.8 --asn                     # trace with ASN/org/country per hop
./ipx.py example.org -T --port 443 --mtu   # TCP trace, then path MTU
./ipx.py 8.8.8.8 1.1.1.1 --compare         # compare hosts/protocols
./ipx.py 8.8.8.8 --live                    # live per-hop stats
./ipx.py 8.8.8.8 --ping -c 10
./ipx.py example.org --scan 22,80,443 --open
```

### Country list to MikroTik

```sh
./country2subnet.py IR            # writes ./iplookup-results/ir_ipv4_prefixes.txt
./mikrotik_subnet_updater.py      # asks for country, router IP, username, password
```

- Run both from the same directory; the updater reads the file the first script wrote.
- The router needs RouterOS 7.1+ with the REST API enabled (`www-ssl` or `www` under `/ip service`) and a user with firewall write access.
- Only the difference is applied, so the list is never emptied during an update. Other address-lists are not touched, and nothing changes until you confirm.

### Optional extras for `ssl_checker.py`

- `pip install cryptography` lets it show issuer and expiry even for certificates that fail verification.
- The `openssl` command-line tool is used for the decoded `.txt` written by `--dump-cert`.
- E-mail alerts use `--smtp-host/--smtp-port/--smtp-user/--smtp-pass` (or the `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` environment variables).

### Optional API keys for `ripe_ip_checker.py`

Set these environment variables to enable extra reputation and compliance checks. Without them the matching checks are skipped.

`ABUSEIPDB_API_KEY`, `IPQS_API_KEY`, `OTX_API_KEY`, `GREYNOISE_API_KEY`, `IPINFO_TOKEN`, `SHODAN_API_KEY`, `SPAMHAUS_DQS_KEY`, `OPENSANCTIONS_API_KEY`

## Notes

- Country lists show where address space is *registered*, which is not always where it is used or geolocated.
- Be considerate with the public APIs; the scripts are meant for occasional lookups, not bulk scraping.
