package checker

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxies-checker/internal/models"

	"golang.org/x/net/proxy"
)

var ipPattern = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$`)

// Maximum bytes to read from any response body (64 KB is more than enough).
const maxBodyBytes = 64 * 1024

// IPChecker defines an IP-checking endpoint.
type IPChecker struct {
	URL    string
	Format string // "json" or "text"
	Key    string // JSON key for IP extraction
}

var ipCheckers = map[string]IPChecker{
	"ipify":     {URL: "https://api.ipify.org/?format=json", Format: "json", Key: "ip"},
	"httpbin":   {URL: "https://httpbin.org/ip", Format: "json", Key: "origin"},
	"httpbun":   {URL: "https://httpbun.com/ip", Format: "json", Key: "origin"},
	"icanhazip": {URL: "https://icanhazip.com/", Format: "text"},
	"ifconfig":  {URL: "https://ifconfig.me/ip", Format: "text"},
}

var manualChecker = struct {
	URL        string
	SuccessKey string
}{
	URL:        "https://www.jetbrains.com",
	SuccessKey: `<meta name="application-name" content="JetBrains">`,
}

// FailReason categorises proxy check failures.
type FailReason string

const (
	FailTimeout           FailReason = "timeout"
	FailConnectionRefused FailReason = "connection_refused"
	FailHTTPError         FailReason = "http_error"
	FailTransparent       FailReason = "transparent"
	FailInvalidResponse   FailReason = "invalid_response"
	FailInvalidFormat     FailReason = "invalid_format"
	FailOther             FailReason = "other"
)

// proxyJob is a unit of work for the fixed worker pool.
type proxyJob struct {
	addr      string
	proxyType models.ProxyType
}

// ProxyChecker validates proxies using IP-checker endpoints or manual keyword matching.
type ProxyChecker struct {
	manualMode      bool
	checkerChain    []IPChecker
	checkerName     string
	maxWorkers      int
	maxRetries      int
	timeoutConnect  time.Duration
	timeoutRead     time.Duration
	attemptDeadline time.Duration
	realIP          string
	realIPMu        sync.Mutex
	realIPReady     chan struct{}
}

// New creates a new ProxyChecker.
func New(checkerName string, maxWorkers int, timeoutConnect, timeoutRead time.Duration, maxRetries int) (*ProxyChecker, error) {
	pc := &ProxyChecker{
		maxWorkers:      maxWorkers,
		maxRetries:      maxRetries,
		timeoutConnect:  timeoutConnect,
		timeoutRead:     timeoutRead,
		attemptDeadline: timeoutConnect + timeoutRead + 5*time.Second,
	}

	if checkerName == "manual" {
		pc.manualMode = true
		pc.checkerName = "manual"
		slog.Info("ProxyChecker initialized", "mode", "manual", "workers", maxWorkers, "retries", maxRetries)
		return pc, nil
	}

	primary, ok := ipCheckers[checkerName]
	if !ok {
		return nil, fmt.Errorf("unknown checker %q", checkerName)
	}

	pc.checkerName = checkerName
	pc.checkerChain = []IPChecker{primary}
	for _, name := range slices.Sorted(maps.Keys(ipCheckers)) {
		if name != checkerName {
			pc.checkerChain = append(pc.checkerChain, ipCheckers[name])
		}
	}

	slog.Info("ProxyChecker initialized",
		"checker", checkerName, "fallback_chain", len(pc.checkerChain),
		"workers", maxWorkers, "retries", maxRetries,
		"timeout_connect", timeoutConnect, "timeout_read", timeoutRead)

	return pc, nil
}

func (pc *ProxyChecker) detectRealIP(ctx context.Context) {
	if pc.currentRealIP() != "" {
		return
	}

	ready, leader := pc.beginRealIPDetection()
	if !leader {
		if ready == nil {
			return
		}
		select {
		case <-ready:
			return
		case <-ctx.Done():
			return
		}
	}

	source, ip := detectRealIPValue(ctx)
	pc.finishRealIPDetection(ip)
	if ip != "" {
		slog.Info("Detected real IP", "source", source, "ip", ip)
		return
	}

	if ctx.Err() == nil {
		slog.Warn("Could not detect real IP; transparent proxy filtering disabled.")
	}
}

func (pc *ProxyChecker) beginRealIPDetection() (<-chan struct{}, bool) {
	pc.realIPMu.Lock()
	defer pc.realIPMu.Unlock()

	if pc.realIP != "" {
		return nil, false
	}
	if pc.realIPReady != nil {
		return pc.realIPReady, false
	}

	pc.realIPReady = make(chan struct{})
	return pc.realIPReady, true
}

func (pc *ProxyChecker) finishRealIPDetection(ip string) {
	pc.realIPMu.Lock()
	defer pc.realIPMu.Unlock()

	if pc.realIP == "" {
		pc.realIP = ip
	}
	if pc.realIPReady != nil {
		close(pc.realIPReady)
		pc.realIPReady = nil
	}
}

func (pc *ProxyChecker) currentRealIP() string {
	pc.realIPMu.Lock()
	defer pc.realIPMu.Unlock()
	return pc.realIP
}

// DetectRealIP ensures the current public IP is discovered and cached.
func (pc *ProxyChecker) DetectRealIP(ctx context.Context) {
	pc.detectRealIP(ctx)
}

// RealIP returns the cached public IP used for transparent-proxy detection.
func (pc *ProxyChecker) RealIP() string {
	return pc.currentRealIP()
}

// SwapIPCheckersForTesting replaces the IP-checker catalog and returns a restore function.
func SwapIPCheckersForTesting(checkers map[string]IPChecker) func() {
	previous := maps.Clone(ipCheckers)
	ipCheckers = maps.Clone(checkers)
	return func() {
		ipCheckers = previous
	}
}

func detectRealIPValue(ctx context.Context) (string, string) {
	client := &http.Client{Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()

	for _, name := range slices.Sorted(maps.Keys(ipCheckers)) {
		checker := ipCheckers[name]
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, checker.URL, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				_ = resp.Body.Close()
			}
			continue
		}
		ip, err := ExtractIP(io.LimitReader(resp.Body, maxBodyBytes), checker)
		_ = resp.Body.Close()
		if err != nil || ip == "" {
			continue
		}
		return name, ip
	}

	return "", ""
}

func ExtractIP(body io.Reader, checker IPChecker) (string, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}

	var raw string
	if checker.Format == "json" {
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			return "", err
		}
		raw, _ = m[checker.Key].(string)
	} else {
		raw = string(data)
	}

	ip := strings.TrimSpace(strings.Split(raw, ",")[0])
	if ipPattern.MatchString(ip) {
		return ip, nil
	}
	return "", fmt.Errorf("no valid IP found")
}

type socks4Dialer struct {
	proxyAddr string
	dialer    net.Dialer
}

func (d *socks4Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, d.proxyAddr)
	if err != nil {
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}

	request, err := buildSOCKS4Request(address)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write(request); err != nil {
		_ = conn.Close()
		return nil, err
	}

	var response [8]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if response[1] != 0x5A {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS4 connect failed with status 0x%02x", response[1])
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func buildSOCKS4Request(address string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid target port %q", portStr)
	}

	request := []byte{0x04, 0x01, byte(port >> 8), byte(port)}
	if ip := net.ParseIP(host).To4(); ip != nil {
		request = append(request, ip...)
		request = append(request, 0x00)
		return request, nil
	}

	request = append(request, 0x00, 0x00, 0x00, 0x01, 0x00)
	request = append(request, host...)
	request = append(request, 0x00)
	return request, nil
}

// buildHTTPClient creates an http.Client that routes through the given proxy.
func buildHTTPClient(proxyAddr string, proxyType models.ProxyType, connectTimeout, readTimeout time.Duration) (*http.Client, error) {
	totalTimeout := connectTimeout + readTimeout

	switch proxyType {
	case models.ProxyTypeHTTP:
		proxyURL, err := url.Parse("http://" + proxyAddr)
		if err != nil {
			return nil, err
		}
		return &http.Client{
			Timeout: totalTimeout,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				DialContext: (&net.Dialer{
					Timeout: connectTimeout,
				}).DialContext,
				ResponseHeaderTimeout: readTimeout,
				DisableKeepAlives:     true,
				MaxIdleConns:          0,
				IdleConnTimeout:       1 * time.Second,
			},
		}, nil

	case models.ProxyTypeSOCKS4, models.ProxyTypeSOCKS5:
		var contextDialer proxy.ContextDialer
		if proxyType == models.ProxyTypeSOCKS4 {
			contextDialer = &socks4Dialer{
				proxyAddr: proxyAddr,
				dialer: net.Dialer{
					Timeout: connectTimeout,
				},
			}
		} else {
			dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, &net.Dialer{
				Timeout: connectTimeout,
			})
			if err != nil {
				return nil, err
			}
			var ok bool
			contextDialer, ok = dialer.(proxy.ContextDialer)
			if !ok {
				return nil, fmt.Errorf("SOCKS dialer does not support DialContext")
			}
		}
		return &http.Client{
			Timeout: totalTimeout,
			Transport: &http.Transport{
				DialContext:           contextDialer.DialContext,
				ResponseHeaderTimeout: readTimeout,
				DisableKeepAlives:     true,
				MaxIdleConns:          0,
				IdleConnTimeout:       1 * time.Second,
			},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported proxy type: %s", proxyType)
	}
}

// BuildHTTPClient creates an http.Client that routes through the given proxy.
func BuildHTTPClient(proxyAddr string, proxyType models.ProxyType, connectTimeout, readTimeout time.Duration) (*http.Client, error) {
	return buildHTTPClient(proxyAddr, proxyType, connectTimeout, readTimeout)
}

// checkSingleAttempt performs one check attempt against the fallback chain.
func (pc *ProxyChecker) checkSingleAttempt(ctx context.Context, proxyAddr string, proxyType models.ProxyType) (*models.CheckedProxy, FailReason) {
	client, err := buildHTTPClient(proxyAddr, proxyType, pc.timeoutConnect, pc.timeoutRead)
	if err != nil {
		return nil, FailInvalidFormat
	}
	defer client.CloseIdleConnections()

	if pc.manualMode {
		return pc.checkManual(ctx, client, proxyAddr, proxyType)
	}
	return pc.checkIPBased(ctx, client, proxyAddr, proxyType)
}

func (pc *ProxyChecker) checkManual(ctx context.Context, client *http.Client, proxyAddr string, proxyType models.ProxyType) (*models.CheckedProxy, FailReason) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manualChecker.URL, nil)
	if err != nil {
		return nil, FailOther
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, ClassifyError(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	elapsed := time.Since(start)

	if resp.StatusCode != http.StatusOK {
		return nil, FailHTTPError
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, FailOther
	}
	if strings.Contains(string(body), manualChecker.SuccessKey) {
		cp := models.NewCheckedProxy(proxyAddr, proxyType.String(), elapsed.Seconds()*1000)
		return &cp, ""
	}
	return nil, FailInvalidResponse
}

func (pc *ProxyChecker) checkIPBased(ctx context.Context, client *http.Client, proxyAddr string, proxyType models.ProxyType) (*models.CheckedProxy, FailReason) {
	var lastFail FailReason = FailOther

	for _, checker := range pc.checkerChain {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, checker.URL, nil)
		if err != nil {
			lastFail = FailOther
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastFail = ClassifyError(err)
			continue
		}
		elapsed := time.Since(start)

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastFail = FailHTTPError
			continue
		}

		returnedIP, err := ExtractIP(io.LimitReader(resp.Body, maxBodyBytes), checker)
		_ = resp.Body.Close()
		if err != nil || returnedIP == "" {
			lastFail = FailInvalidResponse
			continue
		}

		realIP := pc.currentRealIP()
		if realIP != "" && returnedIP == realIP {
			return nil, FailTransparent
		}

		cp := models.NewCheckedProxy(proxyAddr, proxyType.String(), elapsed.Seconds()*1000)
		return &cp, ""
	}
	return nil, lastFail
}

func ClassifyError(err error) FailReason {
	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return FailTimeout
	}
	errStr := err.Error()
	if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "connection reset") {
		return FailConnectionRefused
	}
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
		return FailTimeout
	}
	return FailOther
}

// checkSingle tests a proxy with retries. Uses context-aware sleep between retries.
func (pc *ProxyChecker) checkSingle(ctx context.Context, proxyAddr string, proxyType models.ProxyType, stats *checkStats) *models.CheckedProxy {
	normalizedAddr, ok := models.NormalizeProxyAddr(proxyAddr)
	if !ok {
		stats.invalidFormat.Add(1)
		return nil
	}
	proxyAddr = normalizedAddr

	var lastReason FailReason = FailOther
	for attempt := range pc.maxRetries + 1 {
		attemptCtx, cancel := context.WithTimeout(ctx, pc.attemptDeadline)
		cp, reason := pc.checkSingleAttempt(attemptCtx, proxyAddr, proxyType)
		cancel()

		if cp != nil {
			stats.working.Add(1)
			return cp
		}
		lastReason = reason
		if attempt < pc.maxRetries {
			select {
			case <-time.After(time.Duration(500*(attempt+1)) * time.Millisecond):
			case <-ctx.Done():
				stats.addFailure(lastReason)
				return nil
			}
		}
	}

	stats.addFailure(lastReason)
	return nil
}

// checkStats tracks checking statistics atomically.
type checkStats struct {
	working       atomic.Int64
	invalidFormat atomic.Int64
	failures      sync.Map
}

func (s *checkStats) addFailure(reason FailReason) {
	val, _ := s.failures.LoadOrStore(string(reason), &atomic.Int64{})
	val.(*atomic.Int64).Add(1)
}

func (s *checkStats) failureSummary() string {
	var parts []string
	s.failures.Range(func(key, value any) bool {
		parts = append(parts, fmt.Sprintf("%s=%d", key, value.(*atomic.Int64).Load()))
		return true
	})
	if len(parts) == 0 {
		return "none"
	}
	slices.Sort(parts)
	return strings.Join(parts, ", ")
}

// FilterWorking checks all proxies concurrently using a fixed worker pool and returns working ones sorted by latency.
func (pc *ProxyChecker) FilterWorking(ctx context.Context, proxies []string, proxyType models.ProxyType) []models.CheckedProxy {
	if len(proxies) == 0 {
		slog.Info("No proxies to check.", "type", proxyType.String())
		return nil
	}

	if !pc.manualMode {
		pc.detectRealIP(ctx)
	}

	total := len(proxies)
	slog.Info("Checking proxies", "count", total, "type", proxyType.String())

	stats := &checkStats{}
	var checkedCount atomic.Int64

	jobs := make(chan proxyJob, pc.maxWorkers*2)
	resultsCh := make(chan models.CheckedProxy, min(total, 4096))
	var wg sync.WaitGroup

	for range pc.maxWorkers {
		wg.Go(func() {
			for job := range jobs {
				cp := pc.checkSingle(ctx, job.addr, job.proxyType, stats)

				count := checkedCount.Add(1)
				if count%500 == 0 || count == int64(total) {
					working := stats.working.Load()
					pct := float64(0)
					if count > 0 {
						pct = float64(working) / float64(count) * 100
					}
					slog.Info("Check progress", "type", proxyType.String(), "checked", count,
						"total", total, "working", working, "pct", fmt.Sprintf("%.1f%%", pct))
				}

				if cp != nil {
					resultsCh <- *cp
				}
			}
		})
	}

	// Feed jobs — returns immediately on context cancellation
	go func() {
		defer close(jobs)
		for _, p := range proxies {
			select {
			case jobs <- proxyJob{addr: p, proxyType: proxyType}:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	working := make([]models.CheckedProxy, 0, min(total/10, 4096))
	for cp := range resultsCh {
		working = append(working, cp)
	}

	slices.SortFunc(working, func(a, b models.CheckedProxy) int {
		return cmp.Compare(a.LatencyMs, b.LatencyMs)
	})

	slog.Info("Proxy check complete",
		"type", proxyType.String(), "working", len(working), "total", total,
		"invalid_format", stats.invalidFormat.Load(), "failures", stats.failureSummary())

	return working
}

// IsManualMode returns whether the checker is in manual mode.
func (pc *ProxyChecker) IsManualMode() bool {
	return pc.manualMode
}
