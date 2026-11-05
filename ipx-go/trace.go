package main

import (
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var intr atomic.Bool // set on Ctrl+C

// Hop is one TTL step: all probe results, majority-vote IP and average RTT.
type Hop struct {
	TTL     int
	Results []Res
	IP      string
	Avg     float64
	HasAvg  bool
}

// tracePath traces one path; returns hops and the hop at which the target answered (0 = never).
func tracePath(target, proto string, a *Args, onHop func(*Hop)) ([]*Hop, int) {
	send := makeSender(proto, target, a)
	var hops []*Hop
	for ttl := 1; ttl <= a.MaxHops; ttl++ {
		if intr.Load() {
			break
		}
		results := make([]Res, a.Probes)
		var wg sync.WaitGroup
		for i := 0; i < a.Probes; i++ {
			wg.Add(1)
			go func(i int) { defer wg.Done(); results[i] = send(ttl, i) }(i)
		}
		wg.Wait()

		hop := &Hop{TTL: ttl, Results: results}
		counts, order := map[string]int{}, []string{}
		sum, n := 0.0, 0
		for _, r := range results {
			if r.IP != "" {
				if counts[r.IP] == 0 {
					order = append(order, r.IP)
				}
				counts[r.IP]++
			}
			if r.Has {
				sum += r.RTT
				n++
			}
		}
		best := 0
		for _, ip := range order {
			if counts[ip] > best {
				best, hop.IP = counts[ip], ip
			}
		}
		if n > 0 {
			hop.Avg, hop.HasAvg = sum/float64(n), true
		}
		hops = append(hops, hop)
		if onHop != nil {
			onHop(hop)
		}
		for _, r := range results {
			if r.Reached {
				return hops, ttl
			}
		}
	}
	return hops, 0
}

func protoLabel(proto string, a *Args) string {
	if proto == "tcp" {
		return "TCP:" + strconv.Itoa(a.Port)
	}
	return strings.ToUpper(proto)
}

func runSingle(a *Args, host, target string) ([]*Hop, int) {
	w := barWidth()
	asn := ""
	if a.ASN {
		asn = " / ASN"
	}
	outln("%sTracing%s%s %s (%s%s%s) via %s%s%s, max %d hops\n", BOLD+CYAN, RESET, "", host, MAGENTA, target, RESET,
		YELLOW, protoLabel(a.Proto, a), RESET, a.MaxHops)
	outln("%s%3s  %-16s %-30s HOST%s%s", DIM, "HOP", "IP", "RTTs (ms)", asn, RESET)

	onHop := func(h *Hop) {
		var rtts []string
		for _, r := range h.Results {
			if r.IP != "" {
				rtts = append(rtts, rttColor(r.RTT)+pad6(r.RTT)+RESET)
			} else {
				rtts = append(rtts, RED+"     *"+RESET)
			}
		}
		ipTxt := RED + padR("*", 16) + RESET
		if h.IP != "" {
			ipTxt = MAGENTA + padR(h.IP, 16) + RESET
		}
		line := BOLD + padL(strconv.Itoa(h.TTL), 3) + RESET + "  " + ipTxt + " " +
			strings.Join(rtts, "  ") + "   " + hopInfo(h.IP, a)
		// erase bar, print hop line (scrolls up), redraw bar underneath
		out("\r\033[K%s\n%s", line, bar(h.TTL, a.MaxHops, w, "Tracing"))
	}
	out("%s", bar(0, a.MaxHops, w, "Tracing"))
	hops, reached := tracePath(target, a.Proto, a, onHop)
	if reached > 0 {
		out("\r\033[K%s\n", bar(a.MaxHops, a.MaxHops, w, "Done   "))
		outln("\n%s%sReached %s in %d hops.%s", GREEN, BOLD, target, reached, RESET)
	} else {
		out("\r\033[K%s\n", bar(len(hops), a.MaxHops, w, "Gave up"))
		if !intr.Load() {
			outln("\n%sDid not reach %s within %d hops.%s", RED, target, a.MaxHops, RESET)
		}
	}
	return hops, reached
}

func pad6(v float64) string { return padL(strconv.FormatFloat(v, 'f', 1, 64), 6) }
func padL(s string, n int) string {
	if l := len([]rune(s)); l < n {
		return strings.Repeat(" ", n-l) + s
	}
	return s
}
func padR(s string, n int) string {
	if l := len([]rune(s)); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}

// ----------------------------------------------------------------- compare

type job struct{ label, target, proto string }

func runCompare(a *Args, targets [][2]string) {
	var jobs []job
	if len(targets) > 1 {
		for _, t := range targets {
			jobs = append(jobs, job{t[0], t[1], a.Proto})
		}
	} else {
		var bad []string
		for _, p := range strings.Split(a.Protos, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if p != "icmp" && p != "udp" && p != "tcp" {
				bad = append(bad, p)
				continue
			}
			jobs = append(jobs, job{protoLabel(p, a), targets[0][1], p})
		}
		if len(bad) > 0 {
			die("unknown protocol(s) in --protos: %s", strings.Join(bad, ", "))
		}
		if len(jobs) == 0 {
			die("--protos is empty")
		}
	}

	w := barWidth()
	total := a.MaxHops * len(jobs)
	done := 0
	var mu sync.Mutex
	kind := "protocols"
	if len(targets) > 1 {
		kind = "targets"
	}
	var labels []string
	for _, j := range jobs {
		labels = append(labels, MAGENTA+j.label+RESET)
	}
	outln("%s%sComparing%s %d %s: %s\n", BOLD, CYAN, RESET, len(jobs), kind, strings.Join(labels, ", "))
	draw := func(label string) { out("\r\033[K%s", bar(done, total, w, label)) }

	type outcome struct {
		hops    []*Hop
		reached int
	}
	results := make([]outcome, len(jobs))
	draw("Comparing")
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func(i int, j job) {
			defer wg.Done()
			hops, reached := tracePath(j.target, j.proto, a, func(*Hop) {
				mu.Lock()
				done++
				draw("Comparing")
				mu.Unlock()
			})
			mu.Lock() // unused hops (path shorter than max) count as complete
			done += a.MaxHops - len(hops)
			draw("Comparing")
			mu.Unlock()
			results[i] = outcome{hops, reached}
		}(i, j)
	}
	wg.Wait()
	done = total
	draw("Done     ")
	out("\n\n")
	if intr.Load() {
		return
	}

	const cw = 24
	hdr := DIM + padL("HOP", 3) + "   "
	for _, j := range jobs {
		l := j.label
		if len(l) > cw-2 {
			l = l[:cw-2]
		}
		hdr += padR(l, cw)
	}
	outln("%s", hdr+RESET)
	maxLen := 0
	for _, r := range results {
		if len(r.hops) > maxLen {
			maxLen = len(r.hops)
		}
	}
	firstDiff := 0
	for i := 0; i < maxLen; i++ {
		var cells strings.Builder
		ips := map[string]bool{}
		for _, r := range results {
			switch {
			case i < len(r.hops) && r.hops[i].IP != "":
				h := r.hops[i]
				ips[h.IP] = true
				cells.WriteString(MAGENTA + padR(h.IP, 15) + RESET + rttColor(h.Avg) + padL(strconv.FormatFloat(h.Avg, 'f', 1, 64), 7) + RESET + "  ")
			case i < len(r.hops):
				cells.WriteString(RED + padR("*", 15) + strings.Repeat(" ", 7) + RESET + "  ")
			default:
				cells.WriteString(DIM + padR("-", 15) + strings.Repeat(" ", 7) + RESET + "  ")
			}
		}
		differs := len(ips) > 1
		if differs && firstDiff == 0 {
			firstDiff = i + 1
		}
		mark := " "
		if differs {
			mark = YELLOW + "≠" + RESET
		}
		outln("%s%s %s %s", BOLD, padL(strconv.Itoa(i+1), 3)+RESET, mark, cells.String())
	}

	outln("")
	for i, j := range jobs {
		r := results[i]
		if r.reached > 0 {
			avg := "-"
			if last := r.hops[len(r.hops)-1]; last.HasAvg {
				avg = strconv.FormatFloat(last.Avg, 'f', 1, 64) + " ms"
			}
			outln("  %s%s%s %sreached in %d hops%s, final hop %s", BOLD, padR(j.label, 14), RESET, GREEN, r.reached, RESET, avg)
		} else {
			outln("  %s%s%s %snot reached within %d hops%s", BOLD, padR(j.label, 14), RESET, RED, a.MaxHops, RESET)
		}
	}
	if len(targets) == 1 {
		if firstDiff > 0 {
			outln("\n%sPaths first diverge at hop %d.%s", YELLOW, firstDiff, RESET)
		} else {
			outln("\n%sAll protocols took the same path.%s", GREEN, RESET)
		}
	}
}

// ----------------------------------------------------------------- MTU

func discoverMTU(a *Args, target string, hopIPs []string) int {
	const hdr = 28 // 20 IP + 8 ICMP
	w := barWidth()
	bottleneck := ""

	trySize := func(payload int) (ok bool, hint int, from string) {
		o, exitOK, ran := runPing(time.Duration(a.Timeout+3)*time.Second,
			"-n", "-c", "1", "-M", "do", "-s", strconv.Itoa(payload), "-W", strconv.Itoa(a.Timeout), target)
		if !ran {
			return false, 0, ""
		}
		if m := mtuRE.FindStringSubmatch(o); m != nil {
			hint, _ = strconv.Atoi(m[1])
		}
		if m := fromRE.FindStringSubmatch(o); m != nil {
			from = m[1]
		}
		return exitOK, hint, from
	}

	outln("\n%s%sPath MTU discovery%s to %s%s%s", BOLD, CYAN, RESET, MAGENTA, target, RESET)
	if ok, _, _ := trySize(16); !ok {
		outln("%sNo reply to small DF pings; cannot determine MTU (ICMP blocked?).%s", RED, RESET)
		return 0
	}
	lo, hi := 16, 8972+1 // lo = known good payload, hi = known/assumed bad
	span0 := math.Log2(float64(hi - lo))
	out("%s", bar(0, 100, w, "MTU    "))
	candidates := []int{1472, 8972} // Ethernet, then jumbo
	for hi-lo > 1 && !intr.Load() {
		var mid int
		if len(candidates) > 0 && lo < candidates[0] && candidates[0] < hi {
			mid, candidates = candidates[0], candidates[1:]
		} else {
			var keep []int
			for _, c := range candidates {
				if lo < c && c < hi {
					keep = append(keep, c)
				}
			}
			candidates = keep
			mid = (lo + hi) / 2
		}
		ok, hint, frm := trySize(mid)
		if ok {
			lo = mid
		} else {
			hi = mid
			if hint > 0 && frm != "" { // a router told us its MTU: remember who, jump straight to it
				bottleneck = frm
				if lo < hint-hdr && hint-hdr < hi {
					candidates = append([]int{hint - hdr}, candidates...)
				}
			}
		}
		res := GREEN + "ok" + RESET
		if !ok {
			res = RED + "too big / no reply" + RESET
		}
		span := float64(hi - lo)
		if span < 1 {
			span = 1
		}
		out("\r\033[K  %s B  %s\n%s", padL(strconv.Itoa(mid+hdr), 5), res,
			bar(int(math.Round(100*(1-math.Log2(span)/span0))), 100, w, "MTU    "))
	}
	out("\r\033[K")
	mtu := lo + hdr
	note := ""
	if mtu > 1500 {
		note = " (jumbo frames)"
	}
	outln("%s%sPath MTU: %d bytes%s%s  %s(max payload %d)%s", GREEN, BOLD, mtu, RESET, note, DIM, lo, RESET)
	if bottleneck != "" && mtu < 1500 {
		where := ""
		for i, ip := range hopIPs {
			if ip == bottleneck {
				where = "hop " + strconv.Itoa(i+1) + " "
				break
			}
		}
		outln("%sLimited by %s%s%s", YELLOW, where, bottleneck, RESET)
	}
	return mtu
}
