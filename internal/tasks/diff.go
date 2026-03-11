package tasks

import (
	"armur-codescanner/internal/logger"
	"fmt"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/utils/merkletrie"
)

// ChangedFiles returns the list of files that changed between the current
// HEAD and the given base reference (e.g., "HEAD~1", "main", a full SHA).
// All returned paths are absolute, resolved against repoPath.
// Returns nil (not an error) when the ref cannot be resolved — callers
// should fall back to a full scan in that case.
func ChangedFiles(repoPath, baseRef string) ([]string, error) {
	if baseRef == "" {
		return nil, fmt.Errorf("baseRef must not be empty")
	}

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("could not open git repository at %s: %w", repoPath, err)
	}

	// Resolve HEAD.
	headRef, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("could not resolve HEAD: %w", err)
	}
	headCommit, err := repo.CommitObject(headRef.Hash())
	if err != nil {
		return nil, fmt.Errorf("could not get HEAD commit: %w", err)
	}

	// Resolve the base ref (branch name, tag, or commit hash).
	baseHash, err := resolveRef(repo, baseRef)
	if err != nil {
		logger.Warn().Str("ref", baseRef).Err(err).Msg("could not resolve base ref; falling back to full scan")
		return nil, nil //nolint:nilerr // intentional fallback
	}
	baseCommit, err := repo.CommitObject(baseHash)
	if err != nil {
		return nil, fmt.Errorf("could not get base commit: %w", err)
	}

	// Compute the diff between base tree and HEAD tree.
	baseTree, err := baseCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("could not get base tree: %w", err)
	}
	headTree, err := headCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("could not get HEAD tree: %w", err)
	}

	changes, err := baseTree.Diff(headTree)
	if err != nil {
		return nil, fmt.Errorf("could not diff trees: %w", err)
	}

	seen := make(map[string]struct{})
	var files []string
	for _, change := range changes {
		action, err := change.Action()
		if err != nil {
			continue
		}
		// Include modified and added files; skip pure deletions.
		switch action {
		case merkletrie.Modify, merkletrie.Insert:
			name := change.To.Name
			if name == "" {
				name = change.From.Name
			}
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				files = append(files, filepath.Join(repoPath, name))
			}
		}
	}

	logger.Info().Str("base", baseRef).Int("changed_files", len(files)).Msg("diff computed")
	return files, nil
}

// resolveRef tries to resolve a ref string to a plumbing.Hash.
// It tries branch, tag, and raw hash in that order.
func resolveRef(repo *git.Repository, ref string) (plumbing.Hash, error) {
	// Try as a symbolic ref or branch.
	hashRef, err := repo.ResolveRevision(plumbing.Revision(ref))
	if err == nil {
		return *hashRef, nil
	}

	// Try as a tag.
	tagRef, err := repo.Tag(ref)
	if err == nil {
		tagObj, err := repo.TagObject(tagRef.Hash())
		if err == nil {
			return tagObj.Target, nil
		}
		return tagRef.Hash(), nil
	}

	// Try as a raw commit hash.
	h := plumbing.NewHash(ref)
	if !h.IsZero() {
		return h, nil
	}

	return plumbing.ZeroHash, fmt.Errorf("could not resolve ref %q", ref)
}
