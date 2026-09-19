package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"proxies-checker/internal/checker"
	"proxies-checker/internal/models"
	"proxies-checker/internal/scraper"
)

const (
	scrapedDir = "proxies/scraped_proxies"
	checkedDir = "proxies/checked_proxies"
	readmePath = "README.md"

	readmeStatsStartMarker = "<!-- generated:stats:start -->"
	readmeStatsEndMarker   = "<!-- generated:stats:end -->"
)

var timeNow = func() time.Time {
	return time.Now().UTC()
}

// Manager orchestrates the scrape → dedupe → check → save pipeline.
type Manager struct {
	sources []scraper.Source
	checker *checker.ProxyChecker
}

// New creates a new Manager.
func New(sources []scraper.Source, chk *checker.ProxyChecker) *Manager {
	return &Manager{sources: sources, checker: chk}
}

// Run executes the full pipeline and returns (totalScraped, totalChecked, err).
func (m *Manager) Run(ctx context.Context) (int, int, error) {
	if err := ensureDirs(); err != nil {
		return 0, 0, err
	}

	// Nothing may be written if the manual target itself is unhealthy.
	if err := m.checker.ValidateTarget(ctx); err != nil {
		return 0, 0, fmt.Errorf("manual target preflight: %w", err)
	}

	raw := scraper.FetchAll(ctx, m.sources)
	deduped := dedupe(raw)
	var runErr error
	if err := saveScraped(deduped); err != nil {
		runErr = errors.Join(runErr, err)
	}
	totalScraped := deduped.Total()
	slog.Info("Total unique scraped proxies", "count", totalScraped)

	checked := m.check(ctx, deduped)
	if err := ctx.Err(); err != nil {
		// A cancelled run must not overwrite previously published results.
		return totalScraped, 0, errors.Join(runErr, err)
	}
	if checked.Total() == 0 && m.checker.IsManualMode() {
		// Zero working proxies is suspicious in manual mode: make sure the target is still healthy
		// before publishing empty lists.
		if err := m.checker.ValidateTarget(ctx); err != nil {
			return totalScraped, 0, errors.Join(runErr, fmt.Errorf("manual target recheck after zero working proxies: %w", err))
		}
	}
	if err := saveChecked(checked); err != nil {
		runErr = errors.Join(runErr, err)
	}
	totalChecked := checked.Total()
	slog.Info("Total checked (working) proxies", "count", totalChecked)

	if err := updateReadme(totalScraped, totalChecked); err != nil {
		runErr = errors.Join(runErr, err)
	}
	return totalScraped, totalChecked, runErr
}

func ensureDirs() error {
	var errs error
	for _, d := range []string{scrapedDir, checkedDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			slog.Error("Failed to create directory", "path", d, "err", err)
			errs = errors.Join(errs, fmt.Errorf("create %s: %w", d, err))
		}
	}
	return errs
}

func dedupe(result *models.ProxyResult) *models.ProxyResult {
	return &models.ProxyResult{
		HTTP:   Normalize(result.HTTP),
		SOCKS4: Normalize(result.SOCKS4),
		SOCKS5: Normalize(result.SOCKS5),
	}
}

func Normalize(proxies []string) []string {
	seen := make(map[string]struct{}, len(proxies))
	result := make([]string, 0, len(proxies))
	for _, p := range proxies {
		normalized, ok := models.NormalizeProxyAddr(p)
		if !ok {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	slices.Sort(result)
	return result
}

func (m *Manager) check(ctx context.Context, result *models.ProxyResult) *models.CheckedResult {
	checked := &models.CheckedResult{}

	var wg sync.WaitGroup
	wg.Go(func() {
		checked.HTTP = m.checker.FilterWorking(ctx, result.HTTP, models.ProxyTypeHTTP)
	})
	wg.Go(func() {
		checked.SOCKS4 = m.checker.FilterWorking(ctx, result.SOCKS4, models.ProxyTypeSOCKS4)
	})
	wg.Go(func() {
		checked.SOCKS5 = m.checker.FilterWorking(ctx, result.SOCKS5, models.ProxyTypeSOCKS5)
	})
	wg.Wait()

	return checked
}

func saveScraped(result *models.ProxyResult) error {
	var errs error
	for _, item := range []struct {
		proto   models.ProxyType
		proxies []string
	}{
		{models.ProxyTypeHTTP, result.HTTP},
		{models.ProxyTypeSOCKS4, result.SOCKS4},
		{models.ProxyTypeSOCKS5, result.SOCKS5},
	} {
		path := filepath.Join(scrapedDir, item.proto.String()+".txt")
		content := strings.Join(item.proxies, "\n")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			slog.Error("Failed to save scraped proxies", "path", path, "err", err)
			errs = errors.Join(errs, fmt.Errorf("save scraped %s: %w", path, err))
			continue
		}
		slog.Info("Saved scraped proxies", "count", len(item.proxies), "proto", item.proto, "path", path)
	}
	return errs
}

func saveChecked(result *models.CheckedResult) error {
	var errs error
	for _, item := range []struct {
		proto   models.ProxyType
		proxies []models.CheckedProxy
	}{
		{models.ProxyTypeHTTP, result.HTTP},
		{models.ProxyTypeSOCKS4, result.SOCKS4},
		{models.ProxyTypeSOCKS5, result.SOCKS5},
	} {
		if item.proxies == nil {
			item.proxies = []models.CheckedProxy{}
		}

		// Plain text (ip:port)
		txtPath := filepath.Join(checkedDir, item.proto.String()+".txt")
		lines := make([]string, 0, len(item.proxies))
		for _, cp := range item.proxies {
			lines = append(lines, cp.Address)
		}
		if err := os.WriteFile(txtPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
			slog.Error("Failed to save checked proxies", "path", txtPath, "err", err)
			errs = errors.Join(errs, fmt.Errorf("save checked text %s: %w", txtPath, err))
		}

		// JSON with metadata
		jsonPath := filepath.Join(checkedDir, item.proto.String()+".json")
		data, err := json.MarshalIndent(item.proxies, "", "  ")
		if err != nil {
			slog.Error("Failed to marshal JSON", "proto", item.proto, "err", err)
			errs = errors.Join(errs, fmt.Errorf("marshal %s JSON: %w", item.proto, err))
			continue
		}
		if err := os.WriteFile(jsonPath, data, 0o644); err != nil {
			slog.Error("Failed to save checked proxies", "path", jsonPath, "err", err)
			errs = errors.Join(errs, fmt.Errorf("save checked json %s: %w", jsonPath, err))
			continue
		}

		slog.Info("Saved checked proxies", "count", len(item.proxies), "proto", item.proto, "txt", txtPath, "json", jsonPath)
	}
	return errs
}

func updateReadme(totalScraped, totalChecked int) error {
	data, err := os.ReadFile(readmePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Warn("README not found; skipping update.", "path", readmePath)
			return nil
		}
		slog.Warn("README not found; skipping update.", "path", readmePath)
		return fmt.Errorf("read %s: %w", readmePath, err)
	}

	updated, err := updateReadmeContent(string(data), totalScraped, totalChecked, timeNow())
	if err != nil {
		return err
	}

	if err := os.WriteFile(readmePath, []byte(updated), 0o644); err != nil {
		slog.Error("Failed to update README", "path", readmePath, "err", err)
		return fmt.Errorf("write %s: %w", readmePath, err)
	}
	slog.Info("README updated successfully.", "path", readmePath)
	return nil
}

func updateReadmeContent(content string, totalScraped, totalChecked int, now time.Time) (string, error) {
	block := generatedReadmeStatsBlock(totalScraped, totalChecked, now)
	if strings.Contains(content, readmeStatsStartMarker) {
		return replaceMarkedReadmeStatsBlock(content, block)
	}
	if updated, ok := replaceLegacyReadmeStatsBlock(content, block); ok {
		return updated, nil
	}
	if updated, ok := insertReadmeStatsBlock(content, block); ok {
		return updated, nil
	}
	return "", fmt.Errorf("README is missing %q/%q markers and the '## Last Updated' section", readmeStatsStartMarker, readmeStatsEndMarker)
}

// UpdateReadmeContent updates or inserts the generated README stats block.
func UpdateReadmeContent(content string, totalScraped, totalChecked int, now time.Time) (string, error) {
	return updateReadmeContent(content, totalScraped, totalChecked, now)
}

func generatedReadmeStatsBlock(totalScraped, totalChecked int, now time.Time) string {
	lastUpdated := now.UTC().Format("Monday, 02 January 2006, 15:04:05 UTC")
	return strings.Join([]string{
		readmeStatsStartMarker,
		"**Last Updated**: " + lastUpdated + "<br>",
		fmt.Sprintf("**Total Scraped Proxies**: %d<br>", totalScraped),
		fmt.Sprintf("**Total Checked Proxies**: %d", totalChecked),
		readmeStatsEndMarker,
	}, "\n")
}

func replaceMarkedReadmeStatsBlock(content, block string) (string, error) {
	before, after, ok := strings.Cut(content, readmeStatsStartMarker)
	if !ok {
		return "", fmt.Errorf("README is missing %q", readmeStatsStartMarker)
	}
	_, tail, ok := strings.Cut(after, readmeStatsEndMarker)
	if !ok {
		return "", fmt.Errorf("README is missing %q", readmeStatsEndMarker)
	}
	return before + block + tail, nil
}

func replaceLegacyReadmeStatsBlock(content, block string) (string, bool) {
	var lines []string
	replaced := false

	for line := range strings.SplitSeq(content, "\n") {
		if isLegacyReadmeStatsLine(line) {
			if !replaced {
				lines = append(lines, block)
				replaced = true
			}
			continue
		}
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n"), replaced
}

func insertReadmeStatsBlock(content, block string) (string, bool) {
	var lines []string
	inserted := false

	for line := range strings.SplitSeq(content, "\n") {
		lines = append(lines, line)
		if !inserted && strings.TrimSpace(line) == "## Last Updated" {
			lines = append(lines, block)
			inserted = true
		}
	}

	return strings.Join(lines, "\n"), inserted
}

func isLegacyReadmeStatsLine(line string) bool {
	return strings.HasPrefix(line, "**Last Updated**") ||
		strings.HasPrefix(line, "**Total Scraped Proxies**") ||
		strings.HasPrefix(line, "**Total Proxies**") ||
		strings.HasPrefix(line, "**Total Checked Proxies**")
}
