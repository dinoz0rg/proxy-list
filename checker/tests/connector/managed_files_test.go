package connector_test

import (
	"testing"

	"proxies-checker/internal/connector"

	"github.com/google/go-github/v62/github"
)

func TestManagedFilesUnchangedMatchesCurrentTree(t *testing.T) {
	t.Parallel()

	files := map[string][]byte{"README.md": []byte("hello")}
	entries := []*github.TreeEntry{{Path: new("README.md"), Type: new("blob"), SHA: new("b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0")}}

	if !connector.ManagedFilesUnchanged(entries, files) {
		t.Fatal("expected unchanged managed files to be detected")
	}
}

func TestManagedFilesUnchangedDetectsBlobMismatch(t *testing.T) {
	t.Parallel()

	files := map[string][]byte{"README.md": []byte("hello")}
	entries := []*github.TreeEntry{{Path: new("README.md"), Type: new("blob"), SHA: new("5ea2ed416fbd4a4cbe227b75fe255dd7fa6bd4d6")}}

	if connector.ManagedFilesUnchanged(entries, files) {
		t.Fatal("expected changed managed files to be detected")
	}
}

func TestManagedFilesUnchangedDetectsMissingPath(t *testing.T) {
	t.Parallel()

	files := map[string][]byte{"README.md": []byte("hello")}

	if connector.ManagedFilesUnchanged(nil, files) {
		t.Fatal("expected missing tree entry to be treated as changed")
	}
}
