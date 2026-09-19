package manager_test

import (
	"slices"
	"testing"

	"proxies-checker/internal/manager"
)

func TestNormalizeDeduplicatesAndTrims(t *testing.T) {
	t.Parallel()

	input := []string{"  1.2.3.4:80 ", "5.6.7.8:443", "1.2.3.4:80", "", "  ", "5.6.7.8:443"}
	got := manager.Normalize(input)

	if len(got) != 2 {
		t.Fatalf("expected 2 unique proxies, got %d: %v", len(got), got)
	}
	if got[0] != "1.2.3.4:80" {
		t.Errorf("expected '1.2.3.4:80', got %q", got[0])
	}
	if got[1] != "5.6.7.8:443" {
		t.Errorf("expected '5.6.7.8:443', got %q", got[1])
	}
}

func TestNormalizeEmptyInput(t *testing.T) {
	t.Parallel()

	got := manager.Normalize(nil)
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %v", got)
	}
}

func TestNormalizeAllBlanks(t *testing.T) {
	t.Parallel()

	got := manager.Normalize([]string{"", "  ", "\t"})
	if len(got) != 0 {
		t.Fatalf("expected empty result, got %v", got)
	}
}

func TestNormalizeDropsInvalidProxyAddresses(t *testing.T) {
	t.Parallel()

	got := manager.Normalize([]string{
		"1.2.3.4:80",
		"999.1.1.1:80",
		"5.6.7.8:70000",
		"not-a-proxy",
		"10.0.0.1:8080",
	})

	want := []string{"1.2.3.4:80", "10.0.0.1:8080"}
	if !slices.Equal(got, want) {
		t.Fatalf("expected only valid proxies %v, got %v", want, got)
	}
}
