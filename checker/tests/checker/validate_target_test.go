package checker_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"proxies-checker/internal/checker"
	"proxies-checker/internal/models"
)

const jetbrainsMarkerPage = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="application-name" content="JetBrains"/><title>JetBrains</title></head><body></body></html>`

func newManualChecker(t *testing.T) *checker.ProxyChecker {
	t.Helper()
	pc, err := checker.New("manual", 2, 500*time.Millisecond, 500*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("checker.New: %v", err)
	}
	return pc
}

func TestValidateTargetNonManualIsNoop(t *testing.T) {
	t.Parallel()

	pc, err := checker.New("ipify", 1, time.Second, time.Second, 0)
	if err != nil {
		t.Fatalf("checker.New: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := pc.ValidateTarget(ctx); err != nil {
		t.Fatalf("expected nil for non-manual checker, got %v", err)
	}
}

// The following tests swap the manual target URL (package var) and therefore must not run in parallel.

func TestValidateTargetHealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, jetbrainsMarkerPage)
	}))
	defer server.Close()
	defer checker.SwapManualTargetForTesting(server.URL)()

	if err := newManualChecker(t).ValidateTarget(t.Context()); err != nil {
		t.Fatalf("expected healthy target, got %v", err)
	}
}

func TestValidateTargetZeroTimeoutsUseDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, jetbrainsMarkerPage)
	}))
	defer server.Close()
	defer checker.SwapManualTargetForTesting(server.URL)()

	pc, err := checker.New("manual", 1, 0, 0, 0)
	if err != nil {
		t.Fatalf("checker.New: %v", err)
	}
	if err := pc.ValidateTarget(t.Context()); err != nil {
		t.Fatalf("expected default timeout to allow a healthy check, got %v", err)
	}
}

func TestValidateTargetRejectsNon200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, jetbrainsMarkerPage)
	}))
	defer server.Close()
	defer checker.SwapManualTargetForTesting(server.URL)()

	if err := newManualChecker(t).ValidateTarget(t.Context()); err == nil {
		t.Fatal("expected error for HTTP 503")
	}
}

func TestValidateTargetRejectsMissingMarker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `<html><head><title>Maintenance</title></head><body>Back soon</body></html>`)
	}))
	defer server.Close()
	defer checker.SwapManualTargetForTesting(server.URL)()

	if err := newManualChecker(t).ValidateTarget(t.Context()); err == nil {
		t.Fatal("expected error for page without marker")
	}
}

func TestValidateTargetHonoursTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	defer checker.SwapManualTargetForTesting(server.URL)()

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := newManualChecker(t).ValidateTarget(ctx)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error for unresponsive target")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("ValidateTarget took %v, expected prompt return", elapsed)
	}
}

func TestValidateTargetCancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, jetbrainsMarkerPage)
	}))
	defer server.Close()
	defer checker.SwapManualTargetForTesting(server.URL)()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := newManualChecker(t).ValidateTarget(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// forwardProxyHandler is a minimal HTTP forward proxy for absolute-URI GET requests.
func forwardProxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			http.Error(w, "expected absolute URI", http.StatusBadRequest)
			return
		}
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

func TestManualFilterWorkingAcceptsSelfClosingMarkerThroughProxy(t *testing.T) {
	var targetHits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = io.WriteString(w, jetbrainsMarkerPage)
	}))
	defer target.Close()
	defer checker.SwapManualTargetForTesting(target.URL)()

	proxyServer := httptest.NewServer(forwardProxyHandler())
	defer proxyServer.Close()
	proxyAddr := proxyServer.Listener.Addr().String()

	working := newManualChecker(t).FilterWorking(t.Context(), []string{proxyAddr}, models.ProxyTypeHTTP)
	if len(working) != 1 {
		t.Fatalf("expected proxy %s to be accepted, got %v", proxyAddr, working)
	}
	if working[0].Address != proxyAddr {
		t.Fatalf("expected address %s, got %s", proxyAddr, working[0].Address)
	}
	if targetHits.Load() == 0 {
		t.Fatal("expected target to be reached through the proxy")
	}
}
