package main

import (
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	RESET, BOLD, DIM    = "\033[0m", "\033[1m", "\033[2m"
	RED, GREEN, YELLOW  = "\033[31m", "\033[32m", "\033[33m"
	BLUE, MAGENTA, CYAN = "\033[34m", "\033[35m", "\033[36m"
	sparks              = []rune("▁▂▃▄▅▆▇█")
)

func init() {
	if os.Getenv("NO_COLOR") != "" {
		RESET, BOLD, DIM, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN = "", "", "", "", "", "", "", "", ""
	}
}

func out(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	os.Stdout.WriteString(s)
	if tee != nil {
		tee.write(s)
	}
}
func outln(format string, a ...any) { out(format+"\n", a...) }

func die(format string, a ...any) {
	closeTee()
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}

// teeWriter keeps a plain-text copy of the output (no colors, no progress bars) for -o/--output.
type teeWriter struct {
	mu     sync.Mutex
	f      *os.File
	line   []rune
	paused bool // live view: only the final summary is saved
}

var (
	tee    *teeWriter
	ansiRE = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]")
)

func openTee(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	tee = &teeWriter{f: f}
	return nil
}

func (t *teeWriter) write(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.paused {
		return
	}
	for _, ch := range ansiRE.ReplaceAllString(s, "") {
		switch ch {
		case '\n':
			t.f.WriteString(string(t.line) + "\n")
			t.line = t.line[:0]
		case '\r':
			t.line = t.line[:0] // a redrawn line (progress bar) replaces the previous one
		default:
			t.line = append(t.line, ch)
		}
	}
}

func (t *teeWriter) setPaused(p bool) {
	t.mu.Lock()
	t.paused = p
	t.mu.Unlock()
}

func closeTee() {
	if tee == nil {
		return
	}
	tee.mu.Lock()
	defer tee.mu.Unlock()
	if strings.TrimSpace(string(tee.line)) != "" {
		tee.f.WriteString(string(tee.line) + "\n")
	}
	tee.f.Close()
	tee = nil
}

func rttColor(ms float64) string {
	switch {
	case ms < 50:
		return GREEN
	case ms < 150:
		return YELLOW
	}
	return RED
}

func termCols() int {
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 0 {
		return c
	}
	for _, fd := range []int{1, 2, 0} {
		if ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ); err == nil && ws.Col > 0 {
			return int(ws.Col)
		}
	}
	return 80
}

func barWidth() int {
	w := termCols() - 40
	if w > 40 {
		w = 40
	}
	if w < 10 {
		w = 10
	}
	return w
}

func bar(done, total, width int, label string) string {
	frac := 0.0
	if total > 0 {
		frac = math.Min(1, float64(done)/float64(total))
	}
	filled := int(float64(width) * frac)
	color := GREEN
	if frac < 0.34 {
		color = RED
	} else if frac < 0.67 {
		color = YELLOW
	}
	return fmt.Sprintf("%s%s%s [%s%s%s%s%s] %s%5.1f%%%s %s%d/%d%s",
		BOLD, label, RESET, color, strings.Repeat("█", filled), DIM,
		strings.Repeat("░", width-filled), RESET, color, frac*100, RESET, DIM, done, total, RESET)
}

func sparkline(vals []float64, width int) string {
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	lo, hi, any := math.Inf(1), math.Inf(-1), false
	for _, v := range vals {
		if !math.IsNaN(v) {
			any = true
			lo, hi = math.Min(lo, v), math.Max(hi, v)
		}
	}
	if !any {
		return strings.Repeat(" ", width)
	}
	var sb strings.Builder
	sb.WriteString(strings.Repeat(" ", width-len(vals)))
	for _, v := range vals {
		if math.IsNaN(v) {
			sb.WriteString(RED + "×" + RESET)
			continue
		}
		i := 0
		if hi != lo {
			i = int((v - lo) / (hi - lo) * float64(len(sparks)-1))
		}
		sb.WriteString(rttColor(v) + string(sparks[i]) + RESET)
	}
	return sb.String()
}
