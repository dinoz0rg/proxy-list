package logging_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"proxies-checker/internal/logging"
)

func TestRotateLogArchivesNonEmptyFile(t *testing.T) {
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer func() {
		_ = os.Chdir(originalWD)
	}()

	workDir := t.TempDir()
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	if err := os.MkdirAll("log", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	mainLogPath := filepath.Join("log", "logmain.log")
	if err := os.WriteFile(mainLogPath, []byte("hello log"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	archivedPath, err := logging.RotateLog(mainLogPath, time.Date(2026, time.April, 4, 13, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("RotateLog() error = %v", err)
	}
	if archivedPath == "" {
		t.Fatal("expected rotated log path")
	}
	if _, err := os.Stat(mainLogPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected main log to be moved away, stat err = %v", err)
	}
	content, err := os.ReadFile(archivedPath)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", archivedPath, err)
	}
	if string(content) != "hello log" {
		t.Fatalf("unexpected archived content: %q", content)
	}
}

func TestRotateLogSkipsEmptyFile(t *testing.T) {
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer func() {
		_ = os.Chdir(originalWD)
	}()

	workDir := t.TempDir()
	if err := os.Chdir(workDir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	if err := os.MkdirAll("log", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	mainLogPath := filepath.Join("log", "logmain.log")
	if err := os.WriteFile(mainLogPath, nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	archivedPath, err := logging.RotateLog(mainLogPath, time.Date(2026, time.April, 4, 13, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("RotateLog() error = %v", err)
	}
	if archivedPath != "" {
		t.Fatalf("expected empty file not to be rotated, got %q", archivedPath)
	}
}
