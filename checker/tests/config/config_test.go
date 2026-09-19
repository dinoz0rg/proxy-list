package config_test

import (
	"slices"
	"testing"
	"time"

	"proxies-checker/internal/config"
)

func TestLoadDefaults(t *testing.T) {
	for _, key := range []string{
		"IP_CHECKER", "MAX_WORKERS", "CHECK_TIMEOUT_CONNECT",
		"CHECK_TIMEOUT_READ", "MAX_RETRIES", "SLEEP_SECONDS",
		"RUN_ONCE", "GITHUB_TOKEN", "GITHUB_REPO",
	} {
		t.Setenv(key, "")
	}

	cfg := config.Load()

	if cfg.CheckerName != "ipify" {
		t.Errorf("expected checker 'ipify', got %q", cfg.CheckerName)
	}
	if cfg.MaxWorkers != 100 {
		t.Errorf("expected 100 workers, got %d", cfg.MaxWorkers)
	}
	if cfg.TimeoutConnect != 5*time.Second {
		t.Errorf("expected 5s connect timeout, got %v", cfg.TimeoutConnect)
	}
	if cfg.TimeoutRead != 10*time.Second {
		t.Errorf("expected 10s read timeout, got %v", cfg.TimeoutRead)
	}
	if cfg.MaxRetries != 1 {
		t.Errorf("expected 1 retry, got %d", cfg.MaxRetries)
	}
	if cfg.RunOnce {
		t.Error("expected RunOnce=false")
	}
}

func TestLoadCustomValues(t *testing.T) {
	t.Setenv("IP_CHECKER", "httpbin")
	t.Setenv("MAX_WORKERS", "50")
	t.Setenv("CHECK_TIMEOUT_CONNECT", "3.0")
	t.Setenv("CHECK_TIMEOUT_READ", "7.0")
	t.Setenv("MAX_RETRIES", "3")
	t.Setenv("RUN_ONCE", "true")
	t.Setenv("SLEEP_SECONDS", "3600")

	cfg := config.Load()

	if cfg.CheckerName != "httpbin" {
		t.Errorf("expected 'httpbin', got %q", cfg.CheckerName)
	}
	if cfg.MaxWorkers != 50 {
		t.Errorf("expected 50, got %d", cfg.MaxWorkers)
	}
	if cfg.TimeoutConnect != 3*time.Second {
		t.Errorf("expected 3s, got %v", cfg.TimeoutConnect)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("expected 3, got %d", cfg.MaxRetries)
	}
	if !cfg.RunOnce {
		t.Error("expected RunOnce=true")
	}
}

func TestLoadDurationStrings(t *testing.T) {
	t.Setenv("CHECK_TIMEOUT_CONNECT", "750ms")
	t.Setenv("CHECK_TIMEOUT_READ", "1500ms")

	cfg := config.Load()

	if cfg.TimeoutConnect != 750*time.Millisecond {
		t.Errorf("expected 750ms connect timeout, got %v", cfg.TimeoutConnect)
	}
	if cfg.TimeoutRead != 1500*time.Millisecond {
		t.Errorf("expected 1500ms read timeout, got %v", cfg.TimeoutRead)
	}
}

func TestLoadInvalidCheckerFallsBack(t *testing.T) {
	t.Setenv("IP_CHECKER", "nonexistent")

	cfg := config.Load()

	if cfg.CheckerName != "ipify" {
		t.Errorf("expected fallback to 'ipify', got %q", cfg.CheckerName)
	}
}

func TestLoadInvalidIntUsesDefault(t *testing.T) {
	t.Setenv("MAX_WORKERS", "notanumber")

	cfg := config.Load()

	if cfg.MaxWorkers != 100 {
		t.Errorf("expected default 100, got %d", cfg.MaxWorkers)
	}
}

func TestLoadBelowMinimumUsesMinimum(t *testing.T) {
	t.Setenv("MAX_WORKERS", "0")

	cfg := config.Load()

	if cfg.MaxWorkers != 1 {
		t.Errorf("expected minimum 1, got %d", cfg.MaxWorkers)
	}
}

func TestLoadInvalidBoolUsesDefault(t *testing.T) {
	t.Setenv("RUN_ONCE", "maybe")

	cfg := config.Load()

	if cfg.RunOnce {
		t.Error("expected invalid RUN_ONCE to fall back to false")
	}
}

func TestValidCheckers(t *testing.T) {
	t.Parallel()

	expected := []string{"ipify", "httpbin", "httpbun", "icanhazip", "ifconfig", "manual"}
	for _, name := range expected {
		if !slices.Contains(config.ValidCheckers, name) {
			t.Errorf("expected %q in ValidCheckers", name)
		}
	}
}
