package logging

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const logDir = "log"

func archiveLogPath(now time.Time) string {
	timestamp := strings.NewReplacer(":", "-", " ", "_").Replace(now.UTC().Format("2006-01-02 15:04:05"))
	return filepath.Join(logDir, "logmain("+timestamp+"_UTC).log")
}

func rotateLog(path string, now time.Time) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	if info.Size() == 0 {
		return "", nil
	}

	archivedPath := archiveLogPath(now)
	for attempt := range 100 {
		candidate := archivedPath
		if attempt > 0 {
			candidate = filepath.Join(logDir, strings.TrimSuffix(filepath.Base(archivedPath), ".log")+fmt.Sprintf("_%02d.log", attempt))
		}
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			if err := os.Rename(path, candidate); err != nil {
				return "", err
			}
			return candidate, nil
		}
	}

	return "", fmt.Errorf("could not find a free archive name for %s", path)
}

// RotateLog archives a non-empty log file and returns the archive path.
func RotateLog(path string, now time.Time) (string, error) {
	return rotateLog(path, now)
}

// Init creates the log/ directory and configures slog to write to both
// stdout and log/logmain.log (mirroring the Python helpers.py behaviour).
// It returns a cleanup function that should be deferred by the caller to
// flush and close the log file.
func Init() func() {
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
		slog.Warn("Failed to create log directory, logging to stdout only", "err", err)
		return func() {}
	}

	mainLogPath := filepath.Join(logDir, "logmain.log")
	if archivedPath, err := rotateLog(mainLogPath, time.Now()); err != nil {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
		slog.Warn("Failed to rotate existing log file, logging to stdout only", "path", mainLogPath, "err", err)
		return func() {}
	} else if archivedPath != "" {
		slog.Info("Archived stale log file", "path", archivedPath)
	}

	f, err := os.OpenFile(mainLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
		slog.Warn("Failed to open log file, logging to stdout only", "err", err)
		return func() {}
	}

	multi := io.MultiWriter(os.Stdout, f)
	slog.SetDefault(slog.New(slog.NewTextHandler(multi, &slog.HandlerOptions{Level: slog.LevelInfo})))

	return func() {
		if err := f.Close(); err != nil {
			slog.Warn("Failed to close log file", "path", mainLogPath, "err", err)
			return
		}

		archivedPath, err := rotateLog(mainLogPath, time.Now())
		if err != nil {
			slog.Warn("Failed to archive log file", "from", mainLogPath, "to", archivedPath, "err", err)
			return
		}
		if archivedPath == "" {
			return
		}

		slog.Info("Archived log file", "path", archivedPath)
	}
}
