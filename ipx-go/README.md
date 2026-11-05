# ipx (Go)

Single static binary version of [`ipx.py`](../ipx.py): traceroute over ICMP/UDP/TCP with per-hop ASN, path MTU discovery, protocol/host comparison, live per-hop stats, ping, and TCP/UDP port scan. Linux only, no root needed, no runtime dependencies except the system `ping` command.

## Install

Download the binary for your CPU from the [Releases](https://github.com/dcenterd/IPTools/releases) page:

```sh
tar xzf ipx-1.0.0-linux-amd64.tar.gz     # or linux-arm64
sudo install ipx-1.0.0-linux-amd64/ipx /usr/local/bin/
ipx --help
```

## Usage

Same flags as the Python version:

```sh
ipx 8.8.8.8 --asn                      # trace with ASN/org/country per hop
ipx example.org -T --port 443 --mtu    # TCP trace, then path MTU
ipx 8.8.8.8 1.1.1.1 --compare          # compare hosts
ipx 8.8.8.8 --compare --protos icmp,udp,tcp
ipx 8.8.8.8 --live                     # live per-hop stats
ipx 8.8.8.8 --ping -c 10               # default is 5 probes
ipx example.org --scan 22,80,443 --open
```

Set `NO_COLOR=1` to turn colors off.

## Build from source

```sh
cd ipx-go
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=dev" -o ipx .
go test ./...
```

Notes: as in the Python version, ICMP probes use the system `ping` (needs the `iputils-ping` package); UDP and TCP probes use plain sockets with `IP_RECVERR`. IPv4 only.
