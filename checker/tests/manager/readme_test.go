package manager_test

import (
	"strings"
	"testing"
	"time"

	"proxies-checker/internal/manager"
)

const (
	readmeStatsStartMarker = "<!-- generated:stats:start -->"
	readmeStatsEndMarker   = "<!-- generated:stats:end -->"
)

func TestUpdateReadmeContentReplacesGeneratedBlock(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.April, 4, 12, 30, 45, 0, time.UTC)
	input := strings.Join([]string{
		"# Proxy List",
		"",
		"## Last Updated",
		readmeStatsStartMarker,
		"stale",
		readmeStatsEndMarker,
		"",
		"## Download",
	}, "\n")

	got, err := manager.UpdateReadmeContent(input, 123, 45, now)
	if err != nil {
		t.Fatalf("UpdateReadmeContent() error = %v", err)
	}

	if !strings.Contains(got, "**Last Updated**: Saturday, 04 April 2026, 12:30:45 UTC<br>") {
		t.Fatalf("updated README is missing refreshed timestamp: %s", got)
	}
	if !strings.Contains(got, "**Total Scraped Proxies**: 123<br>") {
		t.Fatalf("updated README is missing scraped count: %s", got)
	}
	if !strings.Contains(got, "**Total Checked Proxies**: 45") {
		t.Fatalf("updated README is missing checked count: %s", got)
	}
}

func TestUpdateReadmeContentMigratesLegacyStatsBlock(t *testing.T) {
	t.Parallel()

	input := strings.Join([]string{
		"# Proxy List",
		"",
		"## Last Updated",
		"**Last Updated**: old<br>",
		"**Total Proxies**: 1<br>",
		"**Total Checked Proxies**: 2",
		"",
		"## Download",
	}, "\n")

	got, err := manager.UpdateReadmeContent(input, 10, 3, time.Date(2026, time.April, 4, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("UpdateReadmeContent() error = %v", err)
	}

	if !strings.Contains(got, readmeStatsStartMarker) || !strings.Contains(got, readmeStatsEndMarker) {
		t.Fatalf("expected generated markers in migrated README: %s", got)
	}
	if strings.Contains(got, "**Total Proxies**") {
		t.Fatalf("expected legacy total line to be replaced: %s", got)
	}
}

func TestUpdateReadmeContentInsertsBlockAfterHeading(t *testing.T) {
	t.Parallel()

	input := "# Proxy List\n\n## Last Updated\n\n## Download\n"
	got, err := manager.UpdateReadmeContent(input, 7, 2, time.Date(2026, time.April, 4, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("UpdateReadmeContent() error = %v", err)
	}

	if !strings.Contains(got, "## Last Updated\n"+readmeStatsStartMarker) {
		t.Fatalf("expected generated block immediately after heading: %s", got)
	}
}
