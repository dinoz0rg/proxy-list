package config

import (
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Config holds all application settings, loaded from environment variables.
type Config struct {
	CheckerName    string
	MaxWorkers     int
	TimeoutConnect time.Duration
	TimeoutRead    time.Duration
	MaxRetries     int
	SleepSeconds   int
	RunOnce        bool
	GitHubToken    string
	GitHubRepo     string
}

// ValidCheckers lists all supported checker names.
var ValidCheckers = []string{"ipify", "httpbin", "httpbun", "icanhazip", "ifconfig", "manual"}

// Load reads configuration from environment variables with defaults and validation.
func Load() *Config {
	c := &Config{
		CheckerName:    envString("IP_CHECKER", "ipify"),
		MaxWorkers:     envInt("MAX_WORKERS", 100, 1),
		TimeoutConnect: envDuration("CHECK_TIMEOUT_CONNECT", 5*time.Second, 500*time.Millisecond),
		TimeoutRead:    envDuration("CHECK_TIMEOUT_READ", 10*time.Second, 500*time.Millisecond),
		MaxRetries:     envInt("MAX_RETRIES", 1, 0),
		SleepSeconds:   envInt("SLEEP_SECONDS", 7200, 0),
		RunOnce:        envBool("RUN_ONCE", false),
		GitHubToken:    os.Getenv("GITHUB_TOKEN"),
		GitHubRepo:     os.Getenv("GITHUB_REPO"),
	}

	c.CheckerName = strings.ToLower(c.CheckerName)
	if !slices.Contains(ValidCheckers, c.CheckerName) {
		slog.Error("Unknown IP_CHECKER, falling back to 'ipify'", "checker", c.CheckerName)
		c.CheckerName = "ipify"
	}

	return c
}

func envString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def, minVal int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		slog.Warn("Invalid env var, using default", "key", key, "value", raw, "default", def)
		return def
	}
	if v < minVal {
		slog.Warn("Env var below minimum, using minimum", "key", key, "value", v, "min", minVal)
		return minVal
	}
	return v
}

func envDuration(key string, def, minVal time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}

	if duration, err := time.ParseDuration(raw); err == nil {
		if duration < minVal {
			slog.Warn("Env var below minimum, using minimum", "key", key, "value", duration, "min", minVal)
			return minVal
		}
		return duration
	}

	seconds, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		slog.Warn("Invalid env var, using default", "key", key, "value", raw, "default", def)
		return def
	}
	duration := time.Duration(seconds * float64(time.Second))
	if duration < minVal {
		slog.Warn("Env var below minimum, using minimum", "key", key, "value", duration, "min", minVal)
		return minVal
	}
	return duration
}

func envBool(key string, def bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch raw {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	case "":
		return def
	default:
		slog.Warn("Invalid env var, using default", "key", key, "value", raw, "default", def)
		return def
	}
}
