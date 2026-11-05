package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	scanTimeout = time.Second
	scanThreads = 100
)

var (
	topTCP = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1723, 3306, 3389, 5432, 5900, 8080, 8443}
	topUDP = []int{53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 4500, 5353}
)

func udpPayload(port int) []byte {
	switch port {
	case 53: // DNS query for "."
		b := make([]byte, 12)
		binary.BigEndian.PutUint16(b[0:], 0x1234)
		binary.BigEndian.PutUint16(b[2:], 0x0100)
		binary.BigEndian.PutUint16(b[4:], 1)
		return append(b, 0, 0, 1, 0, 1)
	case 123: // NTP client request
		b := make([]byte, 48)
		b[0] = 0x1b
		return b
	}
	return []byte{0}
}

func parsePorts(spec string) ([]int, error) {
	set := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, hasRange := strings.Cut(part, "-")
		if !hasRange || hi == "" {
			hi = lo
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("bad port spec '%s'", part)
		}
		if a < 1 || a > b || b > 65535 {
			return nil, fmt.Errorf("port out of range: '%s'", part)
		}
		for p := a; p <= b; p++ {
			set[p] = true
		}
	}
	var ports []int
	for p := range set {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

// scanTCP: open = handshake completed, closed = RST, filtered = no answer.
func scanTCP(target string, port int, timeout time.Duration) (string, float64, bool) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return "filtered", 0, false
	}
	defer unix.Close(fd)
	start := time.Now()
	_ = unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: addr4(target)})
	if _, ok := pollFD(fd, unix.POLLOUT|unix.POLLERR, timeout); !ok {
		return "filtered", 0, false
	}
	rtt := ms(start)
	e, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	switch {
	case err != nil:
		return "filtered", 0, false
	case e == 0:
		return "open", rtt, true
	case e == int(unix.ECONNREFUSED):
		return "closed", rtt, true
	}
	return "filtered", rtt, true
}

// scanUDP: open = got a reply, closed = ICMP port unreachable, open|filtered = silence.
func scanUDP(target string, port int, timeout time.Duration) (string, float64, bool) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return "filtered", 0, false
	}
	defer unix.Close(fd)
	if unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVERR, 1) != nil ||
		unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: addr4(target)}) != nil {
		return "filtered", 0, false
	}
	payload := udpPayload(port)
	for try := 0; try < 2; try++ {
		start := time.Now()
		if _, err := unix.Write(fd, payload); err != nil {
			return "filtered", 0, false
		}
		flags, ok := pollFD(fd, unix.POLLIN|unix.POLLERR, timeout)
		if !ok {
			continue
		}
		rtt := ms(start)
		if flags&unix.POLLERR != 0 {
			if _, t, c, ok := readICMPError(fd); ok {
				if t == 3 && c == 3 {
					return "closed", rtt, true
				}
				return "filtered", rtt, true
			}
			if e, _ := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR); e == int(unix.ECONNREFUSED) {
				return "closed", rtt, true
			}
		} else if flags&unix.POLLIN != 0 {
			if _, err := unix.Read(fd, make([]byte, 2048)); err != nil {
				return "closed", rtt, true
			}
			return "open", rtt, true
		}
	}
	return "open|filtered", 0, false
}

func colorFor(state string) string {
	switch state {
	case "open":
		return GREEN
	case "closed":
		return RED
	}
	return YELLOW
}

var (
	svcOnce sync.Once
	svcMap  = map[string]string{}
)

func serviceName(port int, proto string) string {
	svcOnce.Do(func() {
		for k, v := range map[string]string{"21/tcp": "ftp", "22/tcp": "ssh", "23/tcp": "telnet", "25/tcp": "smtp",
			"53/tcp": "domain", "53/udp": "domain", "67/udp": "bootps", "68/udp": "bootpc", "69/udp": "tftp",
			"80/tcp": "http", "110/tcp": "pop3", "111/tcp": "sunrpc", "123/udp": "ntp", "135/tcp": "epmap",
			"137/udp": "netbios-ns", "138/udp": "netbios-dgm", "139/tcp": "netbios-ssn", "143/tcp": "imap",
			"161/udp": "snmp", "162/udp": "snmp-trap", "443/tcp": "https", "445/tcp": "microsoft-ds",
			"500/udp": "isakmp", "514/udp": "syslog", "993/tcp": "imaps", "995/tcp": "pop3s",
			"1723/tcp": "pptp", "1900/udp": "ssdp", "3306/tcp": "mysql", "3389/tcp": "ms-wbt-server",
			"4500/udp": "ipsec-nat-t", "5353/udp": "mdns", "5432/tcp": "postgresql", "5900/tcp": "vnc",
			"8080/tcp": "http-alt", "8443/tcp": "https-alt"} {
			svcMap[k] = v
		}
		if f, err := os.Open("/etc/services"); err == nil {
			defer f.Close()
			seen := map[string]bool{}
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line, _, _ := strings.Cut(sc.Text(), "#")
				fl := strings.Fields(line)
				if len(fl) >= 2 {
					if !seen[fl[1]] {
						seen[fl[1]] = true
						svcMap[fl[1]] = fl[0]
					}
				}
			}
		}
	})
	return svcMap[strconv.Itoa(port)+"/"+proto]
}

func runScan(a *Args, target string) {
	var protos []string
	if a.Open {
		protos = []string{"tcp", "udp"}
	} else {
		sp := a.ScanProto
		if sp == "" {
			sp = "tcp,udp"
		}
		for _, p := range strings.Split(sp, ",") {
			if p = strings.TrimSpace(p); p != "" {
				protos = append(protos, p)
			}
		}
	}
	bad := len(protos) == 0
	for _, p := range protos {
		if p != "tcp" && p != "udp" {
			bad = true
		}
	}
	if bad {
		die("--scan-proto must be tcp, udp or tcp,udp")
	}
	type task struct {
		proto string
		port  int
	}
	var jobs []task
	for _, proto := range protos {
		var ports []int
		switch {
		case a.Scan == "top" && proto == "tcp":
			ports = topTCP
		case a.Scan == "top":
			ports = topUDP
		default:
			var err error
			if ports, err = parsePorts(a.Scan); err != nil {
				die("%v", err)
			}
		}
		for _, p := range ports {
			jobs = append(jobs, task{proto, p})
		}
	}
	w := barWidth()
	up := make([]string, len(protos))
	for i, p := range protos {
		up[i] = strings.ToUpper(p)
	}
	outln("%s%sPort scan%s %s%s%s  %s%s%s, %d ports, timeout %gs\n", BOLD, CYAN, RESET, MAGENTA, target, RESET,
		YELLOW, strings.Join(up, "+"), RESET, len(jobs), scanTimeout.Seconds())
	outln("%s%11s  %-14s %8s  SERVICE%s", DIM, "PORT", "STATE", "RTT", RESET)

	type result struct {
		proto, state string
		port         int
		rtt          float64
		has          bool
	}
	var results []result
	done := 0
	out("%s", bar(0, len(jobs), w, "Scanning"))
	tasks := make(chan task)
	resCh := make(chan result, scanThreads)
	workers := scanThreads
	if len(jobs) < workers {
		workers = len(jobs)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				var r result
				r.proto, r.port = t.proto, t.port
				if t.proto == "tcp" {
					r.state, r.rtt, r.has = scanTCP(target, t.port, scanTimeout)
				} else {
					r.state, r.rtt, r.has = scanUDP(target, t.port, scanTimeout)
				}
				resCh <- r
			}
		}()
	}
	go func() {
		for _, j := range jobs {
			if intr.Load() {
				break
			}
			tasks <- j
		}
		close(tasks)
		wg.Wait()
		close(resCh)
	}()
	for r := range resCh {
		done++
		results = append(results, r)
		line := ""
		if r.state == "open" || (!a.Open && r.state == "open|filtered") || a.ShowClosed {
			rtt := padL("-", 8)
			if r.has {
				rtt = padL(strconv.FormatFloat(r.rtt, 'f', 1, 64), 6) + "ms"
			}
			line = fmt.Sprintf("%s/%s  %s%s%s %s  %s%s%s\n", padL(strconv.Itoa(r.port), 7), padR(r.proto, 3),
				colorFor(r.state), padR(r.state, 14), RESET, rtt, CYAN, serviceName(r.port, r.proto), RESET)
		}
		out("\r\033[K%s%s", line, bar(done, len(jobs), w, "Scanning"))
	}
	if intr.Load() {
		out("\r\033[K%sInterrupted.%s\n", YELLOW, RESET)
	} else {
		out("\r\033[K%s\n", bar(len(jobs), len(jobs), w, "Done    "))
	}

	outln("\n%sSummary%s", BOLD, RESET)
	for _, proto := range protos {
		counts := map[string]int{}
		for _, r := range results {
			if r.proto == proto {
				counts[r.state]++
			}
		}
		var states []string
		for k := range counts {
			states = append(states, k)
		}
		sort.Strings(states)
		var parts []string
		for _, k := range states {
			parts = append(parts, fmt.Sprintf("%s%d %s%s", colorFor(k), counts[k], k, RESET))
		}
		txt := strings.Join(parts, ", ")
		if txt == "" {
			txt = "no results"
		}
		outln("  %s%s%s %s", BOLD, padR(strings.ToUpper(proto), 4), RESET, txt)
	}
	var opened []string
	sort.Slice(results, func(i, j int) bool {
		if results[i].proto != results[j].proto {
			return results[i].proto < results[j].proto
		}
		return results[i].port < results[j].port
	})
	anyOF := false
	for _, r := range results {
		if r.state == "open" {
			opened = append(opened, fmt.Sprintf("%d/%s", r.port, r.proto))
		}
		if r.state == "open|filtered" {
			anyOF = true
		}
	}
	if len(opened) > 0 {
		outln("  %sopen:%s %s", GREEN, RESET, strings.Join(opened, ", "))
	}
	if !a.Open && anyOF {
		outln("  %sopen|filtered = no reply (UDP services often stay silent, or a firewall drops it)%s", DIM, RESET)
	}
}
