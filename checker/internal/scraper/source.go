package scraper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"proxies-checker/internal/models"
)

const (
	fetchTimeout      = 15 * time.Second
	defaultUA         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	maxBodyBytes      = 10 * 1024 * 1024 // 10 MB cap to prevent OOM
	maxFetchAttempts  = 3
	fetchRetryBackoff = 250 * time.Millisecond
)

// scrapeClient is a dedicated HTTP client for scraping with proper timeouts.
var scrapeClient = &http.Client{
	Timeout: fetchTimeout,
	Transport: &http.Transport{
		DisableKeepAlives: true,
	},
}

// Source defines the interface for a proxy source.
type Source interface {
	Name() string
	Fetch(ctx context.Context) (*models.ProxyResult, error)
}

// httpGet fetches a URL and returns the response body as a string.
func httpGet(ctx context.Context, url string) (string, error) {
	return httpGetWithHeaders(ctx, url, nil)
}

// httpGetWithHeaders fetches a URL with optional headers and returns the response body as a string.
func httpGetWithHeaders(ctx context.Context, url string, headers map[string]string) (string, error) {
	var lastErr error
	for attempt := range maxFetchAttempts {
		body, retry, err := httpGetOnce(ctx, url, headers)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retry || attempt == maxFetchAttempts-1 {
			break
		}

		backoff := time.Duration(attempt+1) * fetchRetryBackoff
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return "", fmt.Errorf("fetching %s: %w", url, ctx.Err())
		}
	}

	return "", lastErr
}

func httpGetOnce(ctx context.Context, url string, headers map[string]string) (string, bool, error) {
	ctx, cancel := context.WithTimeoutCause(ctx, fetchTimeout, fmt.Errorf("fetch timeout exceeded for %s", url))
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", defaultUA)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := scrapeClient.Do(req)
	if err != nil {
		retry := ctx.Err() == nil && !errors.Is(err, context.Canceled)
		return "", retry, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError
		return "", retry, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", true, fmt.Errorf("reading body from %s: %w", url, err)
	}
	return string(body), false, nil
}

// safeFetch wraps a source's Fetch call with panic recovery and logging.
func safeFetch(ctx context.Context, src Source) (result *models.ProxyResult) {
	start := time.Now()
	slog.Info("Fetching proxies", "source", src.Name())
	defer func() {
		if recovered := recover(); recovered != nil {
			slog.Error("Source panicked while fetching proxies", "source", src.Name(), "panic", recovered, "elapsed", time.Since(start))
			result = &models.ProxyResult{}
		}
	}()

	result, err := src.Fetch(ctx)
	if err != nil {
		slog.Error("Failed to fetch proxies", "source", src.Name(), "err", err, "elapsed", time.Since(start))
		return &models.ProxyResult{}
	}
	if result == nil {
		slog.Warn("Source returned nil result", "source", src.Name(), "elapsed", time.Since(start))
		return &models.ProxyResult{}
	}
	slog.Info("Fetched proxies",
		"source", src.Name(), "total", result.Total(), "elapsed", time.Since(start),
		models.ProxyTypeHTTP.String(), len(result.HTTP),
		models.ProxyTypeSOCKS4.String(), len(result.SOCKS4),
		models.ProxyTypeSOCKS5.String(), len(result.SOCKS5))
	return result
}

// SafeFetch wraps a source's Fetch call with panic recovery and logging.
func SafeFetch(ctx context.Context, src Source) *models.ProxyResult {
	return safeFetch(ctx, src)
}
