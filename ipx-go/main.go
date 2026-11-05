// ipx - network diagnostic toolkit: traceroute (ICMP/UDP), ping, path MTU,
// protocol comparison, live hop stats and TCP/UDP port check/scan. Linux, no root needed.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

// Args holds the parsed command line.
type Args struct {
	Hosts                          []string
	MaxHops, Probes, Timeout, Port int
	Proto, Protos, Scan, ScanProto string
	Output, Bind                   string
	Listen                         int
	PortSet, Tcp                   bool
	ASN, MTU, Compare, Live, Ping  bool
	Open, ShowClosed, NoDNS        bool
	Interval                       float64
	Count, PingCount               int
}

const helpText = `usage: ipx [-h] [-m MAX_HOPS] [-q PROBES] [-w TIMEOUT] [-P {icmp,udp}]
           [-U] [-T] [--port PORT] [-a] [--mtu] [--compare]
           [--protos PROTOS] [--live] [--interval INTERVAL] [--count COUNT]
           [--ping] [-c PING_COUNT] [--scan [PORTS]] [--scan-proto PROTO]
           [--open] [--show-closed] [-o FILE] [-n] [--version]
           host [host ...]
       ipx -l PORT [--bind ADDR]

Network diagnostics: traceroute (ICMP/UDP) with per-hop ASN, ping, path MTU,
protocol comparison, live hop stats and TCP/UDP port check/scan. Linux, no root.

positional arguments:
  host

options:
  -h, --help            show this help message and exit
  -m, --max-hops MAX_HOPS   (default 30)
  -q, --probes PROBES       probes per hop (default 3)
  -w, --timeout TIMEOUT     per-probe timeout in seconds (default 1)
  -P, --proto {icmp,udp}
                        trace probe type (default: icmp)
  -U, --udp             trace: UDP probes; with --port: check UDP only
  -T, --tcp             with --port: check TCP only (-T -U = both, the default)
  --port PORT           nc-style check of this destination port on TCP and/or
                        UDP, instead of tracing
  -a, --asn             show ASN / org / country per hop
  --mtu                 discover path MTU after tracing
  --compare             compare protocols for one host (several hosts are
                        always compared)
  --protos PROTOS       compare: protocols to run (default icmp,udp)
  --live                keep probing every hop and draw live stats (q to quit)
  --interval INTERVAL   live/ping: seconds between rounds (default 1)
  --count COUNT         live mode: stop after N rounds (0 = forever)
  --ping                ping the host instead of tracing: ICMP, or a TCP port
                        ping when combined with --port
  -c, --ping-count N    ping: number of probes (default 5)
  --scan [PORTS]        port scan instead of tracing: 'top' (default), or
                        e.g. 22,80,8000-8100
  --scan-proto PROTO    scan: tcp, udp or tcp,udp (default); on its own it
                        starts a scan of the common ports
  --open                scan for open ports on both TCP and UDP, listing only
                        confirmed-open ones (uses the common-port list unless
                        --scan PORTS is given)
  --show-closed         scan: also list closed/filtered ports
  -o, --output FILE     also save the results as plain text (no colors) to
                        FILE; the live view saves its final summary
  -l, --listen PORT     listen on this TCP port like nc -l: accept one
                        connection, then relay stdin/stdout (no host needed)
  --bind ADDR           listen: address to bind (default 0.0.0.0)
  -n, --no-dns          skip reverse DNS
  --version             print version
`

func usageErr(format string, a ...any) {
	fmt.Fprint(os.Stderr, strings.SplitN(helpText, "\n\n", 2)[0]+"\n")
	fmt.Fprintf(os.Stderr, "ipx: error: "+format+"\n", a...)
	os.Exit(2)
}

type optKind int

const (
	kBool optKind = iota
	kValue
	kOptValue
)

type option struct {
	short, long string
	kind        optKind
	set         func(a *Args, v string)
}

var scanValRE = regexp.MustCompile(`^(top|[0-9][0-9,\-]*)$`)

func parseArgs(argv []string) *Args {
	a := &Args{MaxHops: 30, Probes: 3, Timeout: 1, Port: 443, Protos: "icmp,udp", Bind: "0.0.0.0",
		Interval: 1, PingCount: 5}
	atoi := func(name string, v string) int {
		n, err := strconv.Atoi(v)
		if err != nil {
			usageErr("argument %s: invalid int value: '%s'", name, v)
		}
		return n
	}
	opts := []option{
		{"m", "max-hops", kValue, func(a *Args, v string) { a.MaxHops = atoi("-m/--max-hops", v) }},
		{"q", "probes", kValue, func(a *Args, v string) { a.Probes = atoi("-q/--probes", v) }},
		{"w", "timeout", kValue, func(a *Args, v string) { a.Timeout = atoi("-w/--timeout", v) }},
		{"P", "proto", kValue, func(a *Args, v string) {
			if v != "icmp" && v != "udp" {
				usageErr("argument -P/--proto: invalid choice: '%s' (choose from icmp, udp)", v)
			}
			a.Proto = v
		}},
		{"U", "udp", kBool, func(a *Args, _ string) { a.Proto = "udp" }},
		{"T", "tcp", kBool, func(a *Args, _ string) { a.Tcp = true }},
		{"", "port", kValue, func(a *Args, v string) { a.Port, a.PortSet = atoi("--port", v), true }},
		{"l", "listen", kValue, func(a *Args, v string) { a.Listen = atoi("-l/--listen", v) }},
		{"", "bind", kValue, func(a *Args, v string) { a.Bind = v }},
		{"o", "output", kValue, func(a *Args, v string) { a.Output = v }},
		{"a", "asn", kBool, func(a *Args, _ string) { a.ASN = true }},
		{"", "mtu", kBool, func(a *Args, _ string) { a.MTU = true }},
		{"", "compare", kBool, func(a *Args, _ string) { a.Compare = true }},
		{"", "protos", kValue, func(a *Args, v string) { a.Protos = v }},
		{"", "live", kBool, func(a *Args, _ string) { a.Live = true }},
		{"", "interval", kValue, func(a *Args, v string) {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				usageErr("argument --interval: invalid float value: '%s'", v)
			}
			a.Interval = f
		}},
		{"", "count", kValue, func(a *Args, v string) { a.Count = atoi("--count", v) }},
		{"", "ping", kBool, func(a *Args, _ string) { a.Ping = true }},
		{"c", "ping-count", kValue, func(a *Args, v string) { a.PingCount = atoi("-c/--ping-count", v) }},
		{"", "scan", kOptValue, func(a *Args, v string) {
			if v == "" {
				v = "top"
			}
			a.Scan = v
		}},
		{"", "scan-proto", kValue, func(a *Args, v string) { a.ScanProto = v }},
		{"", "open", kBool, func(a *Args, _ string) { a.Open = true }},
		{"", "show-closed", kBool, func(a *Args, _ string) { a.ShowClosed = true }},
		{"n", "no-dns", kBool, func(a *Args, _ string) { a.NoDNS = true }},
	}
	find := func(short, long string) *option {
		for i := range opts {
			if (short != "" && opts[i].short == short) || (long != "" && opts[i].long == long) {
				return &opts[i]
			}
		}
		return nil
	}

	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--":
			a.Hosts = append(a.Hosts, argv[i+1:]...)
			i = len(argv)
		case arg == "-h" || arg == "--help":
			fmt.Print(helpText)
			os.Exit(0)
		case arg == "--version":
			fmt.Println("ipx", version)
			os.Exit(0)
		case strings.HasPrefix(arg, "--"):
			name, val, hasVal := strings.Cut(arg[2:], "=")
			o := find("", name)
			if o == nil {
				usageErr("unrecognized arguments: %s", arg)
			}
			switch o.kind {
			case kBool:
				if hasVal {
					usageErr("argument --%s: ignored explicit argument '%s'", name, val)
				}
				o.set(a, "")
			case kValue:
				if !hasVal {
					if i+1 >= len(argv) {
						usageErr("argument --%s: expected one argument", name)
					}
					i++
					val = argv[i]
				}
				o.set(a, val)
			case kOptValue:
				if !hasVal && i+1 < len(argv) && scanValRE.MatchString(argv[i+1]) {
					i++
					val = argv[i]
				}
				o.set(a, val)
			}
		case len(arg) > 1 && arg[0] == '-':
			// short options, possibly bundled (-aT) or with attached value (-m10)
			for j := 1; j < len(arg); j++ {
				o := find(string(arg[j]), "")
				if o == nil {
					usageErr("unrecognized arguments: -%c", arg[j])
				}
				if o.kind == kBool {
					o.set(a, "")
					continue
				}
				val := arg[j+1:]
				if val == "" {
					if i+1 >= len(argv) {
						usageErr("argument -%s: expected one argument", o.short)
					}
					i++
					val = argv[i]
				}
				o.set(a, val)
				break
			}
		default:
			a.Hosts = append(a.Hosts, arg)
		}
	}
	if a.Listen != 0 {
		if a.Listen < 1 || a.Listen > 65535 {
			usageErr("--listen port must be 1-65535")
		}
		return a
	}
	if len(a.Hosts) == 0 {
		usageErr("the following arguments are required: host")
	}
	if a.MaxHops < 1 || a.Probes < 1 || a.Timeout < 1 || a.PingCount < 1 {
		usageErr("-m, -q, -w and -c must be at least 1")
	}
	if a.Tcp && !a.PortSet {
		usageErr("-T only applies to a port check: use --port N (for a port scan use --scan-proto)")
	}
	if a.PortSet && (a.Port < 1 || a.Port > 65535) {
		usageErr("--port must be 1-65535")
	}
	return a
}

func resolve(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		return ip.To4().String()
	}
	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
		}
		err = fmt.Errorf("no IPv4 address")
	}
	die("cannot resolve %s: %v", host, err)
	return ""
}

func main() {
	code := run()
	closeTee()
	os.Exit(code)
}

var pingHints = map[string]string{
	"debian": "apt install iputils-ping", "ubuntu": "apt install iputils-ping",
	"fedora": "dnf install iputils", "rhel": "dnf install iputils", "centos": "dnf install iputils",
	"rocky": "dnf install iputils", "almalinux": "dnf install iputils",
	"alpine": "apk add iputils", "arch": "pacman -S iputils",
	"opensuse": "zypper install iputils", "suse": "zypper install iputils",
}

// checkPrereqs fails early with an install hint when the system ping is needed but missing.
func checkPrereqs(needsPing bool) {
	if !needsPing {
		return
	}
	if _, err := exec.LookPath("ping"); err == nil {
		return
	}
	ids := map[string]bool{}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok && (k == "ID" || k == "ID_LIKE") {
				for _, f := range strings.Fields(strings.ToLower(strings.Trim(v, `"`))) {
					ids[f] = true
				}
			}
		}
	}
	hint := "install the iputils package for your distro"
	for k, h := range pingHints {
		if ids[k] {
			hint = "install it with: " + h
			break
		}
	}
	die("`ping` not found (needed for ICMP traces, --ping, --mtu and --live).\n  %s\n  or use --port / --scan / -U (UDP trace), which don't need it", hint)
}

func run() int {
	a := parseArgs(os.Args[1:])

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		intr.Store(true)
		<-sig
		os.Exit(130) // second Ctrl+C: stop immediately
	}()

	if a.Listen != 0 {
		return runListen(a.Bind, a.Listen)
	}
	udpSel := a.Proto == "udp"
	checkProtos := []string{"udp"}
	switch {
	case a.Tcp == udpSel:
		checkProtos = []string{"tcp", "udp"}
	case a.Tcp:
		checkProtos = []string{"tcp"}
	}
	if a.Proto == "" {
		a.Proto = "icmp"
	}
	portOnly := a.PortSet || a.Scan != "" || a.Open || a.ScanProto != "" || a.ShowClosed
	needsPing := (a.Ping && !a.PortSet) || a.MTU ||
		(a.Compare && ((len(a.Hosts) > 1 && a.Proto != "udp") || strings.Contains(a.Protos, "icmp"))) ||
		(!portOnly && !a.Compare && a.Proto != "udp")
	checkPrereqs(needsPing)
	if a.Output != "" {
		if err := openTee(a.Output); err != nil {
			die("cannot write %s: %v", a.Output, err)
		}
	}
	comparing := a.Compare || len(a.Hosts) > 1
	if comparing && (a.Live || a.MTU) {
		die("--live and --mtu cannot be combined with compare mode")
	}
	var targets [][2]string
	for _, h := range a.Hosts {
		targets = append(targets, [2]string{h, resolve(h)})
	}

	interrupted := func() int {
		out("\r\033[K")
		outln("%sInterrupted.%s", YELLOW, RESET)
		return 130
	}

	if (a.Open || a.ScanProto != "" || a.ShowClosed) && a.Scan == "" {
		a.Scan = "top" // scan options on their own imply a scan
	}
	if a.Ping || a.Scan != "" || a.PortSet {
		if len(targets) > 1 {
			die("--ping/--scan/--port take a single host")
		}
		rc := 0
		if a.Ping {
			rc = runPingCmd(a, targets[0][1])
		}
		if a.Scan != "" && !intr.Load() {
			if a.Ping {
				outln("")
			}
			runScan(a, targets[0][1])
		}
		if a.PortSet && !a.Ping && !intr.Load() { // with --ping, --port is the ping target
			if a.Scan != "" {
				outln("")
			}
			rc = runCheck(a, targets[0][1], checkProtos)
		}
		if intr.Load() {
			return 130
		}
		return rc
	}
	if comparing {
		runCompare(a, targets)
		if intr.Load() {
			return interrupted()
		}
		return 0
	}

	host, target := targets[0][0], targets[0][1]
	var hops []*Hop
	if a.Live {
		// discover the path silently; the live view is the only output
		out("%sDiscovering path to %s ...%s", DIM, target, RESET)
		hops, _ = tracePath(target, a.Proto, a, nil)
		out("\r\033[K")
		found := false
		for _, h := range hops {
			found = found || h.IP != ""
		}
		if !found && !intr.Load() {
			die("no hops discovered towards %s", target)
		}
	} else {
		hops, _ = runSingle(a, host, target)
	}
	if intr.Load() {
		return interrupted()
	}
	hopIPs := make([]string, len(hops))
	for i, h := range hops {
		hopIPs[i] = h.IP
	}
	if a.MTU {
		discoverMTU(a, target, hopIPs)
		if intr.Load() {
			return interrupted()
		}
	}
	if a.Live && len(hops) > 0 {
		time.Sleep(time.Second)
		runLive(a, target, hopIPs, makeSender(a.Proto, target, a))
	}
	return 0
}
