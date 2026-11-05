package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

func errf(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }

// runListen is nc -l: accept one TCP connection, then relay stdin -> peer and peer -> stdout.
// Status goes to stderr so stdout carries only the data.
func runListen(bind string, port int) int {
	ln, err := net.Listen("tcp4", net.JoinHostPort(bind, strconv.Itoa(port)))
	if err != nil {
		hint := ""
		if errors.Is(err, syscall.EACCES) {
			hint = " (ports below 1024 need root)"
		}
		die("cannot listen on %s:%d: %v%s", bind, port, errors.Unwrap(errors.Unwrap(err)), hint)
	}
	errf("%s%sListening%s on %s%s%s:%s%d%s/tcp  %sCtrl+C to quit%s", BOLD, CYAN, RESET, MAGENTA, bind, RESET, YELLOW, port, RESET, DIM, RESET)

	var conn net.Conn
	stop := make(chan struct{})
	defer close(stop)
	go func() { // Ctrl+C closes the listener / connection
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				if intr.Load() {
					ln.Close()
					if c := connPtr.Load(); c != nil {
						(*c).Close()
					}
					return
				}
			}
		}
	}()
	conn, err = ln.Accept()
	ln.Close()
	if err != nil {
		if intr.Load() {
			errf("\n%sInterrupted.%s", YELLOW, RESET)
			return 130
		}
		die("accept failed: %v", err)
	}
	connPtr.Store(&conn)
	defer conn.Close()
	errf("%sConnection from%s %s%s%s", GREEN, RESET, MAGENTA, conn.RemoteAddr(), RESET)

	var sent, recvd int64
	go func() { // stdin -> peer; on EOF stop sending but keep receiving
		io.Copy(countWriter{conn, &sent}, os.Stdin)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	n, _ := io.Copy(os.Stdout, conn)
	recvd = n
	errf("%sConnection closed (%d bytes sent, %d bytes received)%s", DIM, atomic.LoadInt64(&sent), recvd, RESET)
	return 0
}

var connPtr atomic.Pointer[net.Conn]

type countWriter struct {
	w io.Writer
	n *int64
}

func (c countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	atomic.AddInt64(c.n, int64(n))
	return n, err
}
