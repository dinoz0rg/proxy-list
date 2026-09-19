package connector_test

import (
	"testing"

	"proxies-checker/internal/connector"
)

func TestParseRepoValid(t *testing.T) {
	t.Parallel()

	owner, name, err := connector.ParseRepo("user/repo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "user" {
		t.Errorf("expected owner 'user', got %q", owner)
	}
	if name != "repo" {
		t.Errorf("expected name 'repo', got %q", name)
	}
}

func TestParseRepoInvalid(t *testing.T) {
	t.Parallel()

	_, _, err := connector.ParseRepo("noslash")
	if err == nil {
		t.Fatal("expected error for invalid repo format")
	}
}

func TestParseRepoRejectsExtraSegments(t *testing.T) {
	t.Parallel()

	_, _, err := connector.ParseRepo("owner/repo/extra")
	if err == nil {
		t.Fatal("expected error for repo path with extra segments")
	}
}

func TestHasProxyPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{"checked_proxies/http.txt", true},
		{"scraped_proxies/socks5.txt", true},
		{"README.md", false},
		{".gitignore", false},
	}
	for _, tt := range tests {
		if got := connector.HasProxyPrefix(tt.path); got != tt.want {
			t.Errorf("HasProxyPrefix(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
