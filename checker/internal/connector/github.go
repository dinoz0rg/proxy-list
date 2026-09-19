package connector

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/go-github/v62/github"
)

// AllowedPaths lists the only files that should be pushed to the GitHub repo.
var AllowedPaths = []string{
	"README.md",
	".gitignore",
	"checked_proxies/http.txt",
	"checked_proxies/socks4.txt",
	"checked_proxies/socks5.txt",
	"checked_proxies/http.json",
	"checked_proxies/socks4.json",
	"checked_proxies/socks5.json",
	"scraped_proxies/http.txt",
	"scraped_proxies/socks4.txt",
	"scraped_proxies/socks5.txt",
}

type managedFile struct {
	repoPath  string
	localPath string
	content   []byte
	blobSHA   string
}

// CommitAll commits only allowed files to the GitHub repository.
// It updates the latest tree so non-managed repository files are preserved.
func CommitAll(ctx context.Context, token, repo string) error {
	if token == "" || repo == "" {
		slog.Warn("GITHUB_TOKEN or GITHUB_REPO not set; skipping commit.")
		return nil
	}

	owner, repoName, err := ParseRepo(repo)
	if err != nil {
		return fmt.Errorf("invalid GITHUB_REPO: %w", err)
	}

	files, err := collectManagedFiles(AllowedPaths)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		slog.Info("No allowed files found — nothing to commit.")
		return nil
	}

	client := github.NewClient(nil).WithAuthToken(token)

	// Get default branch and latest commit
	repoObj, _, err := client.Repositories.Get(ctx, owner, repoName)
	if err != nil {
		return fmt.Errorf("getting repo: %w", err)
	}
	branch := repoObj.GetDefaultBranch()

	ref, _, err := client.Git.GetRef(ctx, owner, repoName, "refs/heads/"+branch)
	if err != nil {
		return fmt.Errorf("getting ref: %w", err)
	}

	latestCommit, _, err := client.Git.GetCommit(ctx, owner, repoName, ref.GetObject().GetSHA())
	if err != nil {
		return fmt.Errorf("getting latest commit: %w", err)
	}
	tree, _, err := client.Git.GetTree(ctx, owner, repoName, latestCommit.Tree.GetSHA(), true)
	if err != nil {
		return fmt.Errorf("getting tree: %w", err)
	}
	if managedFilesUnchanged(tree.Entries, files) {
		slog.Info("Managed files unchanged — skipping commit.")
		return nil
	}

	entries, err := createTreeEntries(ctx, client, owner, repoName, files)
	if err != nil {
		return err
	}

	baseTreeSHA := latestCommit.Tree.GetSHA()
	newTree, _, err := client.Git.CreateTree(ctx, owner, repoName, baseTreeSHA, entries)
	if err != nil {
		return fmt.Errorf("creating tree: %w", err)
	}

	// Create commit
	newCommit, _, err := client.Git.CreateCommit(ctx, owner, repoName, &github.Commit{
		Message: new("Updated Proxies"),
		Tree:    newTree,
		Parents: []*github.Commit{latestCommit},
	}, nil)
	if err != nil {
		return fmt.Errorf("creating commit: %w", err)
	}

	// Update ref
	ref.Object.SHA = newCommit.SHA
	if _, _, err := client.Git.UpdateRef(ctx, owner, repoName, ref, false); err != nil {
		return fmt.Errorf("updating ref: %w", err)
	}

	slog.Info("Batch commit completed successfully.")
	return nil
}

func HasProxyPrefix(path string) bool {
	return strings.HasPrefix(path, "checked_proxies/") || strings.HasPrefix(path, "scraped_proxies/")
}

func ParseRepo(repo string) (owner, name string, err error) {
	parts := strings.Split(strings.TrimSpace(repo), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("expected 'owner/repo' format, got %q", repo)
	}
	return parts[0], parts[1], nil
}

func collectManagedFiles(paths []string) ([]managedFile, error) {
	sortedPaths := slices.Clone(paths)
	slices.Sort(sortedPaths)

	files := make([]managedFile, 0, len(sortedPaths))
	for _, rel := range sortedPaths {
		local := filepath.FromSlash(rel)
		if HasProxyPrefix(rel) {
			local = filepath.FromSlash("proxies/" + rel)
		}
		if _, err := os.Stat(local); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("stat %s: %w", local, err)
		}

		content, err := os.ReadFile(local)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", local, err)
		}
		files = append(files, managedFile{
			repoPath:  rel,
			localPath: local,
			content:   content,
			blobSHA:   gitBlobSHA(content),
		})
	}

	return files, nil
}

func managedFilesUnchanged(treeEntries []*github.TreeEntry, files []managedFile) bool {
	if len(files) == 0 {
		return true
	}

	entriesByPath := make(map[string]*github.TreeEntry, len(treeEntries))
	for _, entry := range treeEntries {
		if entry == nil {
			continue
		}
		entriesByPath[entry.GetPath()] = entry
	}

	for _, file := range files {
		entry, ok := entriesByPath[file.repoPath]
		if !ok || entry.GetType() != "blob" || entry.GetSHA() != file.blobSHA {
			return false
		}
	}

	return true
}

func ManagedFilesUnchanged(treeEntries []*github.TreeEntry, files map[string][]byte) bool {
	managed := make([]managedFile, 0, len(files))
	for path, content := range files {
		managed = append(managed, managedFile{
			repoPath: path,
			content:  content,
			blobSHA:  gitBlobSHA(content),
		})
	}
	return managedFilesUnchanged(treeEntries, managed)
}

func createTreeEntries(ctx context.Context, client *github.Client, owner, repoName string, files []managedFile) ([]*github.TreeEntry, error) {
	entries := make([]*github.TreeEntry, 0, len(files))
	for _, file := range files {
		blob, _, err := client.Git.CreateBlob(ctx, owner, repoName, &github.Blob{
			Content:  new(string(file.content)),
			Encoding: new("utf-8"),
		})
		if err != nil {
			return nil, fmt.Errorf("creating blob for %s: %w", file.repoPath, err)
		}

		entries = append(entries, &github.TreeEntry{
			Path: new(file.repoPath),
			Mode: new("100644"),
			Type: new("blob"),
			SHA:  blob.SHA,
		})
	}

	return entries, nil
}

func gitBlobSHA(content []byte) string {
	hash := sha1.New()
	_, _ = fmt.Fprintf(hash, "blob %d\x00", len(content))
	_, _ = hash.Write(content)
	return hex.EncodeToString(hash.Sum(nil))
}
