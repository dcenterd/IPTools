# ipx (Go)

Single static binary version of [`ipx.py`](../ipx.py): traceroute over ICMP/UDP with per-hop ASN, path MTU discovery, protocol/host comparison, live per-hop stats (`q` to quit), ping (plus a TCP port ping with `--ping --port N` for when ICMP is blocked), an nc-style TCP/UDP port check (`--port`), an `nc -l` style TCP listener (`-l PORT`) and port scan. `-o FILE` saves a plain-text copy of the results. Linux only, no root needed, no runtime dependencies except the system `ping` command.

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
ipx example.org --mtu                  # ICMP trace, then path MTU
ipx example.org --port 443             # nc-style check of TCP and UDP 443
ipx example.org --port 53 -U           # UDP only (-T for TCP only)
ipx -l 8080                            # listen on TCP 8080 like nc -l (--bind ADDR to choose the address)
ipx 8.8.8.8 1.1.1.1 --compare          # compare hosts
ipx 8.8.8.8 --compare --protos icmp,udp
ipx 8.8.8.8 --live                     # live per-hop stats
ipx 8.8.8.8 --ping -c 10               # default is 5 probes
ipx example.org --ping --port 443      # TCP port ping, for when ICMP is blocked
ipx 8.8.8.8 --asn -o trace.txt         # also save a plain-text copy (no colors)
ipx example.org --scan 22,80,443 --open
```

Set `NO_COLOR=1` to turn colors off.

## Build from source

```sh
cd ipx-go
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=dev" -o ipx .
go test ./...
```

Notes: as in the Python version, ICMP probes use the system `ping` (needs the `iputils-ping` package); UDP probes use plain sockets with `IP_RECVERR`; the system `ping` is only needed for ICMP traces, `--ping`, `--mtu` and `--live` (not for `--port`, `--scan` or `-U`). IPv4 only.
