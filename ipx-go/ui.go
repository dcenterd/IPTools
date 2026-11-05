package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

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

func out(format string, a ...any)   { fmt.Fprintf(os.Stdout, format, a...) }
func outln(format string, a ...any) { fmt.Fprintf(os.Stdout, format+"\n", a...) }

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
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
