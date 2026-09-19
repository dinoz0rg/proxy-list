package manager_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proxies-checker/internal/checker"
	"proxies-checker/internal/manager"
	"proxies-checker/internal/models"
	"proxies-checker/internal/scraper"
)

// cancellingSource returns one proxy and cancels the run context, simulating
// a shutdown that arrives after scraping but before checking finishes.
type cancellingSource struct {
	cancel context.CancelFunc
}

func (s *cancellingSource) Name() string { return "cancelling" }

func (s *cancellingSource) Fetch(context.Context) (*models.ProxyResult, error) {
	s.cancel()
	return &models.ProxyResult{HTTP: []string{"127.0.0.1:9"}}, nil
}

const (
	runTestMarkerPage = `<!DOCTYPE html><html><head><meta name="application-name" content="JetBrains"/></head><body></body></html>`
	checkedDir        = "proxies/checked_proxies"
	scrapedDir        = "proxies/scraped_proxies"
	readmePath        = "README.md"
)

// seedWorkspace switches to a temp dir pre-populated with checked files and a README,
// and returns a snapshot of their contents keyed by relative path.
func seedWorkspace(t *testing.T) map[string][]byte {
	t.Helper()
	t.Chdir(t.TempDir())

	if err := os.MkdirAll(checkedDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	files := map[string]string{
		filepath.Join(checkedDir, "http.txt"):    "1.2.3.4:8080\n5.6.7.8:3128",
		filepath.Join(checkedDir, "http.json"):   `[{"address":"1.2.3.4:8080"}]`,
		filepath.Join(checkedDir, "socks4.txt"):  "9.9.9.9:1080",
		filepath.Join(checkedDir, "socks4.json"): `[{"address":"9.9.9.9:1080"}]`,
		filepath.Join(checkedDir, "socks5.txt"):  "8.8.8.8:1080",
		filepath.Join(checkedDir, "socks5.json"): `[{"address":"8.8.8.8:1080"}]`,
		readmePath: strings.Join([]string{
			"# Proxy List",
			"",
			"## Last Updated",
			readmeStatsStartMarker,
			"**Last Updated**: old<br>",
			"**Total Scraped Proxies**: 100<br>",
			"**Total Checked Proxies**: 3",
			readmeStatsEndMarker,
			"",
		}, "\n"),
	}
	snapshot := make(map[string][]byte, len(files))
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
		snapshot[path] = []byte(content)
	}
	return snapshot
}

func assertUnchanged(t *testing.T, snapshot map[string][]byte) {
	t.Helper()
	for path, want := range snapshot {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s was modified:\n got: %q\nwant: %q", path, got, want)
		}
	}
}

func assertScrapedNotWritten(t *testing.T) {
	t.Helper()
	for _, proto := range []string{"http", "socks4", "socks5"} {
		path := filepath.Join(scrapedDir, proto+".txt")
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected %s to be absent, stat err = %v", path, err)
		}
	}
}

func newManualChecker(t *testing.T) *checker.ProxyChecker {
	t.Helper()
	pc, err := checker.New("manual", 2, 500*time.Millisecond, 500*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("checker.New: %v", err)
	}
	return pc
}

// These tests change the working directory and swap the manual target URL; they must stay serial.

func TestRunUnhealthyManualTargetPreservesPublishedFiles(t *testing.T) {
	snapshot := seedWorkspace(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	defer checker.SwapManualTargetForTesting(server.URL)()

	mgr := manager.New([]scraper.Source{}, newManualChecker(t))
	scraped, checked, err := mgr.Run(t.Context())
	if err == nil {
		t.Fatal("expected Run to fail when manual target is unhealthy")
	}
	if !strings.Contains(err.Error(), "manual target preflight") {
		t.Fatalf("expected preflight error, got %v", err)
	}
	if scraped != 0 || checked != 0 {
		t.Fatalf("expected zero counts, got scraped=%d checked=%d", scraped, checked)
	}
	assertUnchanged(t, snapshot)
	assertScrapedNotWritten(t)
}

func TestRunCancelledContextPreservesPublishedFiles(t *testing.T) {
	snapshot := seedWorkspace(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, runTestMarkerPage)
	}))
	defer server.Close()
	defer checker.SwapManualTargetForTesting(server.URL)()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	mgr := manager.New([]scraper.Source{}, newManualChecker(t))
	if _, _, err := mgr.Run(ctx); err == nil {
		t.Fatal("expected Run to fail for a cancelled context")
	}
	assertUnchanged(t, snapshot)
}

func TestRunCancelledDuringCheckPreservesCheckedFiles(t *testing.T) {
	snapshot := seedWorkspace(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, runTestMarkerPage)
	}))
	defer server.Close()
	defer checker.SwapManualTargetForTesting(server.URL)()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	mgr := manager.New([]scraper.Source{&cancellingSource{cancel: cancel}}, newManualChecker(t))
	scraped, checked, err := mgr.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from Run, got %v", err)
	}
	if scraped != 1 || checked != 0 {
		t.Fatalf("expected scraped=1 checked=0, got scraped=%d checked=%d", scraped, checked)
	}

	// Preflight passed, so scraped files are written; checked files and README must be intact.
	if _, err := os.Stat(filepath.Join(scrapedDir, "http.txt")); err != nil {
		t.Fatalf("expected scraped file to exist: %v", err)
	}
	assertUnchanged(t, snapshot)
}

func TestRunZeroWorkingRecheckFailurePreservesCheckedFiles(t *testing.T) {
	snapshot := seedWorkspace(t)

	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) > 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, runTestMarkerPage)
	}))
	defer server.Close()
	defer checker.SwapManualTargetForTesting(server.URL)()

	mgr := manager.New([]scraper.Source{}, newManualChecker(t))
	_, checked, err := mgr.Run(t.Context())
	if err == nil {
		t.Fatal("expected Run to fail when target flips unhealthy before publish")
	}
	if checked != 0 {
		t.Fatalf("expected zero checked, got %d", checked)
	}
	if hits.Load() < 2 {
		t.Fatalf("expected target to be re-validated after zero working proxies, hits=%d", hits.Load())
	}
	assertUnchanged(t, snapshot)
}

func TestRunNonManualZeroSourcesWritesFiles(t *testing.T) {
	seedWorkspace(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, runTestMarkerPage)
	}))
	defer server.Close()
	defer checker.SwapManualTargetForTesting(server.URL)()

	pc, err := checker.New("ipify", 2, 500*time.Millisecond, 500*time.Millisecond, 0)
	if err != nil {
		t.Fatalf("checker.New: %v", err)
	}
	mgr := manager.New([]scraper.Source{}, pc)
	scraped, checked, err := mgr.Run(t.Context())
	if err != nil {
		t.Fatalf("expected Run to succeed, got %v", err)
	}
	if scraped != 0 || checked != 0 {
		t.Fatalf("expected zero counts, got scraped=%d checked=%d", scraped, checked)
	}

	for _, proto := range []string{"http", "socks4", "socks5"} {
		for _, path := range []string{
			filepath.Join(scrapedDir, proto+".txt"),
			filepath.Join(checkedDir, proto+".txt"),
			filepath.Join(checkedDir, proto+".json"),
		} {
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("expected %s to be written: %v", path, err)
			}
		}
		if got, _ := os.ReadFile(filepath.Join(checkedDir, proto+".txt")); len(got) != 0 {
			t.Fatalf("expected empty checked list for %s, got %q", proto, got)
		}
	}
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	if !strings.Contains(string(readme), "**Total Checked Proxies**: 0") {
		t.Fatalf("expected README stats to be updated to 0, got:\n%s", readme)
	}
}
