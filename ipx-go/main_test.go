package main

import (
	"math"
	"net"
	"os"
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	got, err := parsePorts("80,22,8000-8002,22")
	if err != nil || !reflect.DeepEqual(got, []int{22, 80, 8000, 8001, 8002}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"0", "70000", "x", "10-5"} {
		if _, err := parsePorts(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestParseArgs(t *testing.T) {
	a := parseArgs([]string{"example.org", "-aU", "-m10", "--port=8443", "--scan", "22,80", "--open", "-c", "7"})
	if a.Hosts[0] != "example.org" || !a.ASN || a.Proto != "udp" || a.MaxHops != 10 ||
		a.Port != 8443 || a.Scan != "22,80" || !a.Open || a.PingCount != 7 {
		t.Fatalf("unexpected: %+v", a)
	}
	b := parseArgs([]string{"--scan", "example.org"}) // host must not be eaten as ports
	if b.Scan != "top" || len(b.Hosts) != 1 {
		t.Fatalf("unexpected: %+v", b)
	}
	if d := parseArgs([]string{"h"}); d.PingCount != 5 || d.MaxHops != 30 || d.Probes != 3 {
		t.Fatalf("bad defaults: %+v", d)
	}
}

func TestIsGlobal(t *testing.T) {
	for ip, want := range map[string]bool{"8.8.8.8": true, "10.1.1.1": false, "192.168.1.1": false,
		"100.64.0.1": false, "127.0.0.1": false, "172.16.16.1": false, "1.1.1.1": true} {
		if got := isGlobal(net.ParseIP(ip)); got != want {
			t.Errorf("isGlobal(%s)=%v want %v", ip, got, want)
		}
	}
}

func TestSparkline(t *testing.T) {
	NO := math.NaN()
	if got := sparkline([]float64{NO, NO}, 4); got != "    " {
		t.Errorf("empty sparkline %q", got)
	}
	if s := sparkline([]float64{1, 2, 3}, 5); len([]rune(s)) < 5 {
		t.Errorf("short sparkline %q", s)
	}
}

func TestBarClamps(t *testing.T) {
	if bar(5, 0, 10, "x") == "" || bar(99, 10, 10, "x") == "" {
		t.Fatal("bar should render for odd inputs")
	}
}

func TestParseArgsPortCheck(t *testing.T) {
	a := parseArgs([]string{"h", "--port", "53", "-T", "-o", "out.txt"})
	if !a.PortSet || a.Port != 53 || !a.Tcp || a.Output != "out.txt" || a.Proto != "" {
		t.Fatalf("unexpected: %+v", a)
	}
	if b := parseArgs([]string{"h", "-U"}); b.Proto != "udp" || b.PortSet || b.Tcp {
		t.Fatalf("unexpected: %+v", b)
	}
}

func TestTeeStripsColorsAndBars(t *testing.T) {
	path := t.TempDir() + "/o.txt"
	if err := openTee(path); err != nil {
		t.Fatal(err)
	}
	out("%sbold%s line\n", BOLD, RESET)
	out("bar 10%%")
	out("\r\033[Kbar 100%%\n")
	tee.setPaused(true)
	out("hidden\n")
	tee.setPaused(false)
	out("tail")
	closeTee()
	b, _ := os.ReadFile(path)
	if want := "bold line\nbar 100%\ntail\n"; string(b) != want {
		t.Fatalf("got %q want %q", b, want)
	}
}
