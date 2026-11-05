package main

import (
	"math"
	"strconv"
	"time"
)

// pingICMP sends one real ICMP echo via the system ping; returns RTT ms or NaN.
func pingICMP(target string, timeout int) float64 {
	o, ok, ran := runPing(time.Duration(timeout+2)*time.Second, "-n", "-c", "1", "-W", strconv.Itoa(timeout), target)
	if !ran || !ok {
		return math.NaN()
	}
	if m := timeRE.FindStringSubmatch(o); m != nil {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			return v
		}
	}
	return math.NaN()
}

func sleepIntr(d time.Duration) {
	end := time.Now().Add(d)
	for time.Now().Before(end) && !intr.Load() {
		time.Sleep(20 * time.Millisecond)
	}
}

// runPingCmd pings with ICMP, or with --port a TCP port ping (connect RTT). Returns an exit code.
func runPingCmd(a *Args, target string) int {
	tcp := a.PortSet
	if tcp && a.Proto == "udp" {
		die("a port ping is TCP only (UDP has no handshake to time); drop -U")
	}
	kind := "ICMP"
	if tcp {
		kind = "TCP:" + strconv.Itoa(a.Port)
	}
	w := barWidth()
	outln("%s%sPing%s %s%s%s via %s%s%s, %d probes\n", BOLD, CYAN, RESET, MAGENTA, target, RESET, YELLOW, kind, RESET, a.PingCount)
	var rtts []float64
	refused := 0
	out("%s", bar(0, a.PingCount, w, "Pinging"))
	for seq := 1; seq <= a.PingCount && !intr.Load(); seq++ {
		t0 := time.Now()
		state, rtt := "open", math.NaN()
		if tcp {
			var has bool
			state, rtt, has = scanTCP(target, a.Port, time.Duration(a.Timeout)*time.Second)
			if state == "filtered" || !has {
				rtt = math.NaN()
			}
		} else {
			rtt = pingICMP(target, a.Timeout)
		}
		rtts = append(rtts, rtt)
		res := RED + "timeout" + RESET
		timeTxt := "  time " + rttColor(rtt) + padL(strconv.FormatFloat(rtt, 'f', 1, 64), 7) + " ms" + RESET
		switch {
		case math.IsNaN(rtt):
		case state == "closed": // RST: the host answered, the port is closed
			refused++
			res = YELLOW + "port closed (RST)" + RESET + " from " + MAGENTA + target + ":" + strconv.Itoa(a.Port) + RESET + " " + timeTxt
		default:
			at := target
			if tcp {
				at += ":" + strconv.Itoa(a.Port)
			}
			res = GREEN + "reply" + RESET + " from " + MAGENTA + at + RESET + timeTxt
		}
		out("\r\033[K%sseq %s%s  %s\n%s", DIM, padL(strconv.Itoa(seq), 3), RESET, res, bar(seq, a.PingCount, w, "Pinging"))
		if seq < a.PingCount {
			sleepIntr(time.Duration(a.Interval*float64(time.Second)) - time.Since(t0))
		}
	}
	out("\r\033[K")
	sent := len(rtts)
	var ok []float64
	for _, r := range rtts {
		if !math.IsNaN(r) {
			ok = append(ok, r)
		}
	}
	loss := 0.0
	if sent > 0 {
		loss = 100 * float64(sent-len(ok)) / float64(sent)
	}
	lc := RED
	if loss == 0 {
		lc = GREEN
	} else if loss < 20 {
		lc = YELLOW
	}
	outln("%s--- %s ping statistics ---%s", BOLD, target, RESET)
	outln("%d sent, %d received, %s%.1f%% loss%s", sent, len(ok), lc, loss, RESET)
	if refused > 0 {
		outln("%s%d of the replies were RST: the host is up but TCP port %d is closed%s", YELLOW, refused, a.Port, RESET)
	}
	if len(ok) > 0 {
		mn, mx, sum := ok[0], ok[0], 0.0
		for _, v := range ok {
			mn, mx, sum = math.Min(mn, v), math.Max(mx, v), sum+v
		}
		avg := sum / float64(len(ok))
		v := 0.0
		for _, x := range ok {
			v += (x - avg) * (x - avg)
		}
		jitter := math.Sqrt(v / float64(len(ok)))
		outln("min %s%.1f%s / avg %s%.1f%s / max %s%.1f%s / jitter %.1f ms",
			rttColor(mn), mn, RESET, rttColor(avg), avg, RESET, rttColor(mx), mx, RESET, jitter)
		w := len(rtts)
		if w > 60 {
			w = 60
		}
		outln("%s", sparkline(rtts, w))
	}
	nOpen := len(ok) - refused
	if tcp { // one clear verdict for the port
		at := target + ":" + strconv.Itoa(a.Port) + "/tcp"
		switch {
		case sent > 0 && nOpen == sent:
			outln("\n%s%s\u2714 Port ping OK:%s %s%s%s is open (%d/%d replies)", GREEN, BOLD, RESET, MAGENTA, at, RESET, nOpen, sent)
		case nOpen > 0:
			outln("\n%s%s! Port ping partly OK:%s %s%s%s is open but only %d/%d probes were answered", YELLOW, BOLD, RESET, MAGENTA, at, RESET, nOpen, sent)
		case refused > 0:
			outln("\n%s%s! Host is up, port closed:%s %s%s%s refused the connection", YELLOW, BOLD, RESET, MAGENTA, at, RESET)
		default:
			outln("\n%s%s\u2718 Port ping FAILED:%s no answer from %s%s%s (filtered, host down or wrong port)", RED, BOLD, RESET, MAGENTA, at, RESET)
		}
	}
	if len(ok) == 0 || (tcp && nOpen == 0) {
		return 1
	}
	return 0
}
