package checker_test

import (
	"errors"
	"net"
	"strings"
	"testing"

	"proxies-checker/internal/checker"
)

func TestExtractIPJSON(t *testing.T) {
	t.Parallel()

	ip, err := checker.ExtractIP(strings.NewReader(`{"ip": "1.2.3.4"}`), checker.IPChecker{Format: "json", Key: "ip"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "1.2.3.4" {
		t.Fatalf("expected 1.2.3.4, got %s", ip)
	}
}

func TestExtractIPText(t *testing.T) {
	t.Parallel()

	ip, err := checker.ExtractIP(strings.NewReader("  5.6.7.8\n"), checker.IPChecker{Format: "text"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "5.6.7.8" {
		t.Fatalf("expected 5.6.7.8, got %s", ip)
	}
}

func TestExtractIPCommaDelimited(t *testing.T) {
	t.Parallel()

	ip, err := checker.ExtractIP(strings.NewReader("1.2.3.4, 5.6.7.8"), checker.IPChecker{Format: "text"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "1.2.3.4" {
		t.Fatalf("expected 1.2.3.4, got %s", ip)
	}
}

func TestExtractIPInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := checker.ExtractIP(strings.NewReader(`not json`), checker.IPChecker{Format: "json", Key: "ip"})
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestExtractIPNoValidIP(t *testing.T) {
	t.Parallel()

	_, err := checker.ExtractIP(strings.NewReader("not-an-ip"), checker.IPChecker{Format: "text"})
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

type timeoutErr struct{}

func (e *timeoutErr) Error() string   { return "i/o timeout" }
func (e *timeoutErr) Timeout() bool   { return true }
func (e *timeoutErr) Temporary() bool { return false }

func TestClassifyErrorTimeout(t *testing.T) {
	t.Parallel()

	var err net.Error = &timeoutErr{}
	if got := checker.ClassifyError(err); got != checker.FailTimeout {
		t.Fatalf("expected %s, got %s", checker.FailTimeout, got)
	}
}

func TestClassifyErrorConnectionRefused(t *testing.T) {
	t.Parallel()

	err := errors.New("dial tcp: connection refused")
	if got := checker.ClassifyError(err); got != checker.FailConnectionRefused {
		t.Fatalf("expected %s, got %s", checker.FailConnectionRefused, got)
	}
}

func TestClassifyErrorConnectionReset(t *testing.T) {
	t.Parallel()

	err := errors.New("read: connection reset by peer")
	if got := checker.ClassifyError(err); got != checker.FailConnectionRefused {
		t.Fatalf("expected %s, got %s", checker.FailConnectionRefused, got)
	}
}

func TestClassifyErrorDeadlineExceeded(t *testing.T) {
	t.Parallel()

	err := errors.New("context deadline exceeded")
	if got := checker.ClassifyError(err); got != checker.FailTimeout {
		t.Fatalf("expected %s, got %s", checker.FailTimeout, got)
	}
}

func TestClassifyErrorOther(t *testing.T) {
	t.Parallel()

	err := errors.New("something unknown")
	if got := checker.ClassifyError(err); got != checker.FailOther {
		t.Fatalf("expected %s, got %s", checker.FailOther, got)
	}
}