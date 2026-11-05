package main

import (
	"math"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func fnum(v float64) string {
	if math.IsNaN(v) {
		return DIM + padL("-", 7) + RESET
	}
	return rttColor(v) + padL(strconv.FormatFloat(v, 'f', 1, 64), 7) + RESET
}

func ff(v float64) string {
	if math.IsNaN(v) {
		return "-"
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

func runLive(a *Args, target string, hopIPs []string, send func(ttl, i int) Res) {
	n := len(hopIPs)
	cols := termCols()
	width := clamp(cols-12, 20, 100)
	sparkW := clamp(cols-75, 8, 24)
	hist := make([][]float64, n)
	sent, recv := make([]int, n), make([]int, n)
	total := make([]float64, n)
	best, worst, last := nans(n), nans(n), nans(n)
	names := make([]string, n)
	for i, ip := range hopIPs {
		names[i] = hopInfo(ip, a)
	}
	t0 := time.Now()

	render := func(rnd int) {
		var sb []byte
		add := func(s string) { sb = append(sb, s+"\033[K\n"...) }
		add(BOLD + CYAN + "LIVE trace" + RESET + " to " + MAGENTA + target + RESET + " via " + YELLOW + protoLabel(a.Proto, a) + RESET +
			"  " + DIM + "round " + strconv.Itoa(rnd) + "  elapsed " + padL(strconv.Itoa(int(time.Since(t0).Seconds())), 5) + "s  q to quit" + RESET)
		add("")
		add(DIM + padL("HOP", 3) + "  " + padR("IP", 16) + " " + padL("LOSS", 6) + " " + padL("LAST", 7) + " " + padL("AVG", 7) + " " +
			padL("BEST", 7) + " " + padL("WRST", 7) + "  " + padR("HISTORY", sparkW) + "  HOST" + RESET)
		for i := 0; i < n; i++ {
			loss := 0.0
			if sent[i] > 0 {
				loss = 100 * float64(sent[i]-recv[i]) / float64(sent[i])
			}
			lc := RED
			if loss == 0 {
				lc = GREEN
			} else if loss < 20 {
				lc = YELLOW
			}
			avg := math.NaN()
			if recv[i] > 0 {
				avg = total[i] / float64(recv[i])
			}
			ipTxt := RED + padR("*", 16) + RESET
			if hopIPs[i] != "" {
				ipTxt = MAGENTA + padR(hopIPs[i], 16) + RESET
			}
			add(" " + padL(strconv.Itoa(i+1), 2) + "  " + ipTxt + " " + lc + padL(strconv.FormatFloat(loss, 'f', 1, 64), 5) + "%" + RESET + " " +
				fnum(last[i]) + " " + fnum(avg) + " " + fnum(best[i]) + " " + fnum(worst[i]) + "  " +
				sparkline(hist[i], sparkW) + "  " + names[i])
		}
		out("\033[H%s\033[J", strings.TrimSuffix(string(sb), "\n"))
	}

	if tee != nil {
		tee.setPaused(true) // the live screen is not saved, only the final summary
	}
	out("\033[?1049h\033[?25l") // alt screen, hide cursor
	restoreTTY := enableKeys()
	rnd := 0
	type reply struct {
		i   int
		rtt float64
	}
loop:
	for a.Count == 0 || rnd < a.Count {
		rnd++
		ch := make(chan reply, n)
		for i := 0; i < n; i++ {
			go func(i int) {
				r := send(i+1, 0)
				v := math.NaN()
				if r.Has {
					v = r.RTT
				}
				ch <- reply{i, v}
			}(i)
		}
		for k := 0; k < n; k++ {
			r := <-ch
			i := r.i
			sent[i]++
			hist[i] = append(hist[i], r.rtt)
			if len(hist[i]) > width {
				hist[i] = hist[i][len(hist[i])-width:]
			}
			last[i] = r.rtt
			if !math.IsNaN(r.rtt) {
				recv[i]++
				total[i] += r.rtt
				if math.IsNaN(best[i]) || r.rtt < best[i] {
					best[i] = r.rtt
				}
				if math.IsNaN(worst[i]) || r.rtt > worst[i] {
					worst[i] = r.rtt
				}
			}
			render(rnd)
			if intr.Load() || keyQuit() {
				break loop
			}
		}
		deadline := time.Now().Add(time.Duration(a.Interval * float64(time.Second)))
		for time.Now().Before(deadline) && (a.Count == 0 || rnd < a.Count) {
			if intr.Load() || keyQuit() {
				break loop
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	restoreTTY()
	out("\033[?25h\033[?1049l")
	if tee != nil {
		tee.setPaused(false)
	}
	// leave a final snapshot on the normal screen
	outln("%s%sLIVE trace summary%s for %s (%d rounds)", BOLD, CYAN, RESET, target, rnd)
	for i := 0; i < n; i++ {
		loss := 0.0
		if sent[i] > 0 {
			loss = 100 * float64(sent[i]-recv[i]) / float64(sent[i])
		}
		avg := "-"
		if recv[i] > 0 {
			avg = ff(total[i] / float64(recv[i]))
		}
		ip := hopIPs[i]
		if ip == "" {
			ip = "*"
		}
		outln("%s  %s loss %s%%  avg %s ms  best %s ms  worst %s ms", padL(strconv.Itoa(i+1), 3), padR(ip, 16),
			padL(strconv.FormatFloat(loss, 'f', 1, 64), 5), avg, ff(best[i]), ff(worst[i]))
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func nans(n int) []float64 {
	s := make([]float64, n)
	for i := range s {
		s[i] = math.NaN()
	}
	return s
}

// enableKeys switches stdin to single-key mode (no Enter, no echo; Ctrl+C still works).
// It returns a function that restores the terminal; it does nothing if stdin is not a tty.
func enableKeys() func() {
	old, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		return func() {}
	}
	raw := *old
	raw.Lflag &^= unix.ICANON | unix.ECHO
	raw.Cc[unix.VMIN], raw.Cc[unix.VTIME] = 1, 0
	if unix.IoctlSetTermios(0, unix.TCSETS, &raw) != nil {
		return func() {}
	}
	return func() { unix.IoctlSetTermios(0, unix.TCSETS, old) }
}

// keyQuit reports whether q/Q was pressed (non-blocking).
func keyQuit() bool {
	pfd := []unix.PollFd{{Fd: 0, Events: unix.POLLIN}}
	if n, _ := unix.Poll(pfd, 0); n <= 0 || pfd[0].Revents&unix.POLLIN == 0 {
		return false
	}
	buf := make([]byte, 64)
	n, _ := unix.Read(0, buf)
	for _, c := range buf[:max(n, 0)] {
		if c == 'q' || c == 'Q' {
			return true
		}
	}
	return false
}
