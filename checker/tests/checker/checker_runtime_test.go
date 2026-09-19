package checker_test

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"proxies-checker/internal/checker"
	"proxies-checker/internal/models"
)

func TestBuildHTTPClientSOCKS4UsesSOCKS4Handshake(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	firstByte := make(chan byte, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		defer conn.Close()

		var buf [1]byte
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			acceptErr <- err
			return
		}
		firstByte <- buf[0]
	}()

	client, err := checker.BuildHTTPClient(listener.Addr().String(), models.ProxyTypeSOCKS4, 250*time.Millisecond, 250*time.Millisecond)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	defer client.CloseIdleConnections()

	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
		if err != nil {
			return
		}
		_, _ = client.Do(req)
	}()

	select {
	case err := <-acceptErr:
		t.Fatalf("accept/read handshake: %v", err)
	case got := <-firstByte:
		if got != 0x04 {
			t.Fatalf("expected SOCKS4 handshake byte 0x04, got 0x%02x", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proxy handshake")
	}

	<-requestDone
}

func TestDetectRealIPRetriesAfterInitialFailure(t *testing.T) {
	pc := &checker.ProxyChecker{}
	restore := checker.SwapIPCheckersForTesting(map[string]checker.IPChecker{
		"broken": {
			URL:    "http://127.0.0.1:1",
			Format: "text",
		},
	})
	defer restore()

	pc.DetectRealIP(t.Context())
	if got := pc.RealIP(); got != "" {
		t.Fatalf("expected empty real IP after failed detection, got %q", got)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.5")
	}))
	defer server.Close()

	restore = checker.SwapIPCheckersForTesting(map[string]checker.IPChecker{
		"working": {
			URL:    server.URL,
			Format: "text",
		},
	})
	defer restore()

	pc.DetectRealIP(t.Context())
	if got := pc.RealIP(); got != "203.0.113.5" {
		t.Fatalf("expected retry to populate real IP, got %q", got)
	}
}

func TestDetectRealIPDeduplicatesConcurrentLookups(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(w, "203.0.113.10")
	}))
	defer server.Close()

	restore := checker.SwapIPCheckersForTesting(map[string]checker.IPChecker{
		"working": {
			URL:    server.URL,
			Format: "text",
		},
	})
	defer restore()

	pc := &checker.ProxyChecker{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			<-start
			pc.DetectRealIP(t.Context())
		})
	}
	close(start)
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Fatalf("expected exactly one real-IP lookup, got %d", got)
	}
	if got := pc.RealIP(); got != "203.0.113.10" {
		t.Fatalf("expected cached real IP, got %q", got)
	}
}
