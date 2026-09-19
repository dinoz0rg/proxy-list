package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"proxies-checker/internal/checker"
	"proxies-checker/internal/config"
	"proxies-checker/internal/connector"
	"proxies-checker/internal/cycle"
	applog "proxies-checker/internal/logging"
	"proxies-checker/internal/manager"
	"proxies-checker/internal/scraper"
)

func main() {
	closeLog := applog.Init()
	defer closeLog()

	os.Exit(run())
}

func run() int {
	_ = godotenv.Load()

	cfg := config.Load()

	chk, err := checker.New(
		cfg.CheckerName,
		cfg.MaxWorkers,
		cfg.TimeoutConnect,
		cfg.TimeoutRead,
		cfg.MaxRetries,
	)
	if err != nil {
		slog.Error("Failed to create checker", "err", err)
		return 1
	}

	sources := scraper.AllSources()
	mgr := manager.New(sources, chk)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	for {
		slog.Info("Starting scrape-and-check cycle.")
		totalScraped, totalChecked, err := mgr.Run(ctx)
		if err != nil {
			slog.Error("Scrape-and-check cycle completed with errors", "scraped", totalScraped, "checked", totalChecked, "err", err)
		}
		if ctx.Err() != nil {
			slog.Info("Shutting down.")
			return 0
		}
		if err != nil {
			slog.Warn("Skipping GitHub commit because the scrape-and-check cycle had errors.")
			if cfg.RunOnce {
				slog.Info("RUN_ONCE enabled — exiting after one cycle.")
				break
			}

			slog.Info("Sleeping before next cycle", "seconds", cfg.SleepSeconds)
			if !cycle.WaitForNextCycle(ctx, time.Duration(cfg.SleepSeconds)*time.Second) {
				slog.Info("Shutting down.")
				return 0
			}
			continue
		}

		slog.Info("Committing changes to GitHub.")
		if err := connector.CommitAll(ctx, cfg.GitHubToken, cfg.GitHubRepo); err != nil {
			slog.Error("GitHub commit failed", "err", err)
		}
		if ctx.Err() != nil {
			slog.Info("Shutting down.")
			return 0
		}

		if cfg.RunOnce {
			slog.Info("RUN_ONCE enabled — exiting after one cycle.")
			break
		}

		slog.Info("Sleeping before next cycle", "seconds", cfg.SleepSeconds)
		if !cycle.WaitForNextCycle(ctx, time.Duration(cfg.SleepSeconds)*time.Second) {
			slog.Info("Shutting down.")
			return 0
		}
	}
	return 0
}
