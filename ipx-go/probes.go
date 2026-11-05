package main

import (
	"bytes"
	"context"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ipRecvErr      = 11 // IP_RECVERR
	soEeOriginICMP = 2
	udpBasePort    = 33434
)

var (
	fromRE = regexp.MustCompile(`[Ff]rom\s+(\d+\.\d+\.\d+\.\d+)`)
	mtuRE  = regexp.MustCompile(`mtu\s*=\s*(\d+)`)
	timeRE = regexp.MustCompile(`time[=<]([\d.]+)\s*ms`)
)

// Res is one probe result.
type Res struct {
	IP      string
	RTT     float64
	Has     bool // an answer (and RTT) arrived
	Reached bool // the destination itself answered
}

func ms(since time.Time) float64 { return float64(time.Since(since)) / float64(time.Millisecond) }

// runPing runs the system ping; ok is false if it could not run or timed out.
func runPing(limit time.Duration, args ...string) (output string, exitOK, ran bool) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, "ping", args...)
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", false, false
	}
	if _, isExit := err.(*exec.ExitError); err != nil && !isExit {
		return "", false, false // ping missing or not startable
	}
	return buf.String(), err == nil, true
}

func probeICMP(target string, ttl, timeout int) Res {
	start := time.Now()
	o, _, ran := runPing(time.Duration(timeout+2)*time.Second,
		"-n", "-c", "1", "-t", strconv.Itoa(ttl), "-W", strconv.Itoa(timeout), target)
	if !ran {
		return Res{}
	}
	rtt := ms(start)
	m := fromRE.FindStringSubmatch(o)
	if m == nil {
		return Res{}
	}
	reached := strings.Contains(o, "bytes from") && !strings.Contains(o, "exceeded")
	return Res{IP: m[1], RTT: rtt, Has: true, Reached: reached}
}

// readICMPError pops one ICMP error off the socket error queue.
func readICMPError(fd int) (ip string, typ, code uint8, ok bool) {
	buf, oob := make([]byte, 512), make([]byte, 512)
	_, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil {
		return
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return
	}
	for _, m := range msgs {
		if m.Header.Level == unix.SOL_IP && m.Header.Type == ipRecvErr && len(m.Data) >= 24 {
			// struct sock_extended_err: errno u32, origin u8, type u8, code u8, ... offender sockaddr_in at 16
			if m.Data[4] == soEeOriginICMP {
				return net.IP(m.Data[20:24]).String(), m.Data[5], m.Data[6], true
			}
		}
	}
	return
}

// pollFD waits up to timeout; returns revents and whether anything happened.
func pollFD(fd int, events int16, timeout time.Duration) (int16, bool) {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: events}}
	deadline := time.Now().Add(timeout)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return 0, false
		}
		n, err := unix.Poll(pfd, int(left/time.Millisecond)+1)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 {
			return 0, false
		}
		return pfd[0].Revents, true
	}
}

func addr4(s string) [4]byte {
	var a [4]byte
	if ip := net.ParseIP(s).To4(); ip != nil {
		copy(a[:], ip)
	}
	return a
}

func probeUDP(target string, ttl, timeout, port int) Res {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return Res{}
	}
	defer unix.Close(fd)
	if unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl) != nil ||
		unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVERR, 1) != nil {
		return Res{}
	}
	start := time.Now()
	if unix.Sendto(fd, []byte("ipx"), 0, &unix.SockaddrInet4{Port: port, Addr: addr4(target)}) != nil {
		return Res{}
	}
	if _, ok := pollFD(fd, unix.POLLERR|unix.POLLIN, time.Duration(timeout)*time.Second); !ok {
		return Res{}
	}
	rtt := ms(start)
	ip, t, c, ok := readICMPError(fd)
	if !ok {
		return Res{}
	}
	// type 3 / code 3 = port unreachable: the destination answered
	return Res{IP: ip, RTT: rtt, Has: true, Reached: t == 3 && c == 3}
}

// probeTCP sends a SYN. Hop IPs come from ICMP time-exceeded; the target answers
// with SYN/ACK (connected) or RST (refused) - both count as reached.
func probeTCP(target string, ttl, timeout, port int) Res {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return Res{}
	}
	defer unix.Close(fd)
	if unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl) != nil ||
		unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVERR, 1) != nil {
		return Res{}
	}
	start := time.Now()
	_ = unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: addr4(target)}) // EINPROGRESS expected
	if _, ok := pollFD(fd, unix.POLLOUT|unix.POLLERR|unix.POLLIN, time.Duration(timeout)*time.Second); !ok {
		return Res{}
	}
	rtt := ms(start)
	if ip, _, _, ok := readICMPError(fd); ok {
		return Res{IP: ip, RTT: rtt, Has: true}
	}
	if e, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR); err == nil && (e == 0 || e == int(unix.ECONNREFUSED)) {
		return Res{IP: target, RTT: rtt, Has: true, Reached: true}
	}
	return Res{}
}

func makeSender(proto, target string, a *Args) func(ttl, i int) Res {
	switch proto {
	case "udp":
		return func(ttl, i int) Res {
			return probeUDP(target, ttl, a.Timeout, udpBasePort+(ttl-1)*a.Probes+i)
		}
	case "tcp":
		return func(ttl, i int) Res { return probeTCP(target, ttl, a.Timeout, a.Port) }
	}
	return func(ttl, i int) Res { return probeICMP(target, ttl, a.Timeout) }
}

// ----------------------------------------------------------------- DNS / ASN

func reverse(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

var nonGlobal = func() []*net.IPNet {
	var l []*net.IPNet
	for _, c := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		_, n, _ := net.ParseCIDR(c)
		l = append(l, n)
	}
	return l
}()

func isGlobal(ip net.IP) bool {
	for _, n := range nonGlobal {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

var (
	asnMu    sync.Mutex
	asnCache = map[string]string{}
	asnOK    = true
)

// asnLookup returns "AS15169 GOOGLE, US" via Team Cymru whois, "private" for non-global space.
func asnLookup(ipStr string) string {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return ""
	}
	asnMu.Lock()
	if v, ok := asnCache[ipStr]; ok {
		asnMu.Unlock()
		return v
	}
	asnMu.Unlock()
	if !isGlobal(ip) {
		return "private"
	}
	asnMu.Lock()
	ok := asnOK
	asnMu.Unlock()
	if !ok {
		return ""
	}
	text := ""
	conn, err := net.DialTimeout("tcp", "whois.cymru.com:43", 3*time.Second)
	if err != nil {
		asnMu.Lock()
		asnOK = false
		asnCache[ipStr] = ""
		asnMu.Unlock()
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))
	conn.Write([]byte(" -v " + ipStr + "\r\n"))
	var data bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		data.Write(buf[:n])
		if err != nil {
			break
		}
	}
	for _, line := range strings.Split(data.String(), "\n") {
		parts := strings.Split(line, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) >= 7 && isDigits(parts[0]) {
			text = "AS" + parts[0] + " " + parts[6]
		}
	}
	asnMu.Lock()
	asnCache[ipStr] = text
	asnMu.Unlock()
	return text
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// hopInfo is the colored "hostname  [ASN org, CC]" text for a hop.
func hopInfo(ip string, a *Args) string {
	if ip == "" {
		return ""
	}
	s := ""
	if !a.NoDNS {
		if h := reverse(ip); h != "" {
			s = CYAN + h + RESET
		}
	}
	if a.ASN {
		if asn := asnLookup(ip); asn != "" {
			s += "  " + DIM + "[" + RESET + BLUE + asn + RESET + DIM + "]" + RESET
		}
	}
	return s
}
