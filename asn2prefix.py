#!/usr/bin/python3
import ipaddress
import requests

BASE_URL = "https://stat.ripe.net/data"


def ripe_query(endpoint, resource):
    """Query a RIPEstat endpoint; return its data dict ({} on failure)."""
    try:
        response = requests.get(
            f"{BASE_URL}/{endpoint}/data.json",
            params={"resource": resource},
            timeout=20,
        )
        response.raise_for_status()
        return response.json().get("data", {})
    except requests.RequestException as e:
        print(f"WARNING: {endpoint} query failed: {e}")
        return {}


def whois_fields(asn):
    """Collect aut-num / organisation / role fields from the whois record."""
    fields = {}
    for group in ripe_query("whois", asn).get("records", []):
        for r in group:
            fields.setdefault(r["key"], [])
            if r["value"] not in fields[r["key"]]:
                fields[r["key"]].append(r["value"])
    return fields


def show(label, value):
    if value:
        print(f"{label:<12}: {value}")


def header(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


asn = input("Enter AS number (e.g. AS58224): ").strip().upper()

if not asn.startswith("AS"):
    asn = "AS" + asn

overview = ripe_query("as-overview", asn)
whois = whois_fields(asn)
neighbours = ripe_query("asn-neighbours", asn).get("neighbour_counts", {})
announced = ripe_query("announced-prefixes", asn)

# ---------------------------------------------------------------------
# AS owner information
# ---------------------------------------------------------------------
header(f"AS OWNER INFORMATION ({asn})")

block = overview.get("block") or {}
show("Holder", overview.get("holder"))
show("Announcing", "Yes" if overview.get("announced") else "No (not announced now)")
show("AS name", ", ".join(whois.get("as-name", [])))
show("Description", "; ".join(whois.get("descr", [])))
show("Organisation", ", ".join(whois.get("org-name", whois.get("org", []))))
show("Country", ", ".join(whois.get("country", [])))
show("Registry", block.get("name"))
show("Block", f"{block.get('resource')} ({block.get('desc')})" if block.get("resource") else "")
show("Abuse", ", ".join(whois.get("abuse-mailbox", [])))
show("Contacts", ", ".join(whois.get("admin-c", []) + whois.get("tech-c", [])))
show("Created", ", ".join(whois.get("created", [])))
show("Last mod.", ", ".join(whois.get("last-modified", [])))
show("Source", ", ".join(whois.get("source", [])))

# ---------------------------------------------------------------------
# Routing summary
# ---------------------------------------------------------------------
v4, v6 = [], []
for item in announced.get("prefixes", []):
    p = item.get("prefix")
    if not p:
        continue
    try:
        net = ipaddress.ip_network(p, strict=False)
    except ValueError:
        continue
    (v4 if net.version == 4 else v6).append(net)

v4.sort(key=lambda n: (int(n.network_address), n.prefixlen))
v6.sort(key=lambda n: (int(n.network_address), n.prefixlen))

# Count addresses once, even where announced prefixes overlap.
v4_addresses = sum(n.num_addresses for n in ipaddress.collapse_addresses(v4))

header("ROUTING SUMMARY")
print(f"IPv4 prefixes : {len(v4)}")
print(f"IPv4 addresses: {v4_addresses:,}")
print(f"IPv6 prefixes : {len(v6)}")
if neighbours:
    print(
        f"Neighbours    : {neighbours.get('unique', 'n/a')} "
        f"(upstream-side {neighbours.get('left', 'n/a')}, "
        f"downstream-side {neighbours.get('right', 'n/a')})"
    )

# ---------------------------------------------------------------------
# Prefixes
# ---------------------------------------------------------------------
header(f"ANNOUNCED PREFIXES ({len(v4) + len(v6)})")
for net in v4 + v6:
    print(net)
