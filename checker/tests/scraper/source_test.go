package scraper_test

import (
	"context"
	"slices"
	"testing"

	"proxies-checker/internal/models"
	"proxies-checker/internal/scraper"
)

type panicSource struct{}

func (panicSource) Name() string { return "panic" }

func (panicSource) Fetch(context.Context) (*models.ProxyResult, error) {
	panic("boom")
}

type nilResultSource struct{}

func (nilResultSource) Name() string { return "nil" }

func (nilResultSource) Fetch(context.Context) (*models.ProxyResult, error) {
	return nil, nil
}

type stubSource struct {
	name   string
	result *models.ProxyResult
	err    error
}

func (s stubSource) Name() string { return s.name }

func (s stubSource) Fetch(context.Context) (*models.ProxyResult, error) {
	if s.result == nil {
		return &models.ProxyResult{}, s.err
	}
	return s.result, s.err
}

func TestSafeFetchRecoversFromPanic(t *testing.T) {
	t.Parallel()

	result := scraper.SafeFetch(t.Context(), panicSource{})
	if result == nil {
		t.Fatal("expected non-nil result after panic recovery")
	}
	if result.Total() != 0 {
		t.Fatalf("expected empty result after panic recovery, got %+v", result)
	}
}

func TestSafeFetchHandlesNilResult(t *testing.T) {
	t.Parallel()

	result := scraper.SafeFetch(t.Context(), nilResultSource{})
	if result == nil {
		t.Fatal("expected non-nil result for nil source result")
	}
	if result.Total() != 0 {
		t.Fatalf("expected empty result for nil source result, got %+v", result)
	}
}

func TestFetchAllDeduplicatesAndFiltersInvalidProxies(t *testing.T) {
	t.Parallel()

	result := scraper.FetchAll(t.Context(), []scraper.Source{
		stubSource{
			name: "first",
			result: &models.ProxyResult{
				HTTP:   []string{"1.2.3.4:80", "invalid", "1.2.3.4:80"},
				SOCKS4: []string{"5.6.7.8:1080"},
			},
		},
		stubSource{
			name: "second",
			result: &models.ProxyResult{
				HTTP:   []string{"1.2.3.4:80", "10.0.0.1:8080"},
				SOCKS4: []string{"5.6.7.8:1080", "999.1.1.1:9000"},
				SOCKS5: []string{"9.9.9.9:1080"},
			},
		},
	})

	if got, want := result.HTTP, []string{"1.2.3.4:80", "10.0.0.1:8080"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unexpected HTTP proxies: %v", got)
	}
	if got, want := result.SOCKS4, []string{"5.6.7.8:1080"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("unexpected SOCKS4 proxies: %v", got)
	}
	if got, want := result.SOCKS5, []string{"9.9.9.9:1080"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("unexpected SOCKS5 proxies: %v", got)
	}
}

func TestAllSourcesIncludesAdditionalWebsiteSources(t *testing.T) {
	t.Parallel()

	var names []string
	for _, src := range scraper.AllSources() {
		names = append(names, src.Name())
	}

	for _, want := range []string{"AdvancedName", "AnonymousProxy", "Databay", "FlamingoProxies", "FreeProxyUpdate", "FreeProxyUpdateFiltered", "FreeProxyWorld", "HideMn", "IPRoyal", "ProxyDB", "ProxyListOrg", "ProxyListPlus", "ProxyNova", "SocksProxyNet", "SpysOne", "UKProxy"} {
		if !slices.Contains(names, want) {
			t.Fatalf("expected source %q in %v", want, names)
		}
	}
}
