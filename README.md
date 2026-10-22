# IPTools

Small collection of Python network utilities for IP/ASN research and MikroTik address-list automation.

Most scripts query public data sources ([RIPEstat](https://stat.ripe.net), the RIPE Database and the RIR delegated statistics), so they need internet access but no API keys.

## Scripts

| Script | What it does |
|---|---|
| `iplookup.py` | Who is behind an IP (v4/v6)? Shows the announcing prefix and origin ASN, ASN holder, reverse DNS and all prefixes of that ASN. Falls back to the registry record if the IP is not in BGP. |
| `asn2prefix.py` | Given an AS number, prints owner info, a routing summary (prefix and address counts, neighbours) and every announced prefix. |
| `bgp-lg.py` | Looking glass: shows the BGP AS path towards an IP, draws it as a text topology and saves it as a PDF. |
| `prefix-history.py` | Routing history of a prefix or ASN: first/last seen, announced now or not, and the announcement periods. |
| `whois-contacts.py` | Who to contact about an IP, prefix or ASN: abuse contact plus admin/tech contacts with e-mail and phone. |
| `country2subnet.py` | Builds IPv4 prefix lists for one or more countries from the delegated statistics of all five RIRs. Writes plain lists and MikroTik `.rsc` files. |
| `mikrotik_subnet_updater.py` | Syncs a country's prefix list into a MikroTik firewall address-list through the RouterOS REST API (adds missing, removes stale, asks before changing anything). |
| `ripe_ip_checker.py` | Pre-purchase due-diligence report for IPv4 ranges in the RIPE region: ownership, transfers, routing history, RPKI/IRR, reputation, geolocation, past usage, compliance and fragmentation. |

## Requirements

- Python 3.8+
- `requests` (all scripts except `ripe_ip_checker.py`, which uses only the standard library)

```sh
git clone https://github.com/dcenterd/IPTools.git
cd IPTools
pip install -r requirements.txt
```

## Usage

```sh
# who is behind this IP?
./iplookup.py                     # prompts for the IP

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
```

### Country list to MikroTik

```sh
./country2subnet.py IR            # writes ./iplookup-results/ir_ipv4_prefixes.txt
./mikrotik_subnet_updater.py      # asks for country, router IP, username, password
```

- Run both from the same directory; the updater reads the file the first script wrote.
- The router needs RouterOS 7.1+ with the REST API enabled (`www-ssl` or `www` under `/ip service`) and a user with firewall write access.
- Only the difference is applied, so the list is never emptied during an update. Other address-lists are not touched, and nothing changes until you confirm.

### Optional API keys for `ripe_ip_checker.py`

Set these environment variables to enable extra reputation and compliance checks. Without them the matching checks are skipped.

`ABUSEIPDB_API_KEY`, `IPQS_API_KEY`, `OTX_API_KEY`, `GREYNOISE_API_KEY`, `IPINFO_TOKEN`, `SHODAN_API_KEY`, `SPAMHAUS_DQS_KEY`, `OPENSANCTIONS_API_KEY`

## Notes

- Country lists show where address space is *registered*, which is not always where it is used or geolocated.
- Be considerate with the public APIs; the scripts are meant for occasional lookups, not bulk scraping.
