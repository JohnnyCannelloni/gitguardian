// hooks/hooks.go
package hooks

import (
	"fmt"
	"os"
	"path/filepath"
)

// InstallPreCommit finds the repo root, then writes a pre-commit hook
// at .git/hooks/pre-commit to invoke `gitguardian scan` on staged files.
func InstallPreCommit() error {
	// 1) Find the Git repo root by looking upward for .git
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	root := cwd
	for {
		if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			return fmt.Errorf("cannot find .git directory (are you in a Git repository?)")
		}
		root = parent
	}

	// 2) Ensure .git/hooks exists
	hooksDir := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return err
	}

	// 3) Write the hook script
	hookPath := filepath.Join(hooksDir, "pre-commit")
	script := `#!/usr/bin/env bash
set -e

# Determine repo root
ROOT=$(git rev-parse --show-toplevel)
BIN="$ROOT/gitguardian"

# Build gitguardian if not present
if [ ! -x "$BIN" ]; then
    echo "Building gitguardian..."
    cd "$ROOT"
    go build -o gitguardian .
fi

# Get list of staged files
files=$(git diff --cached --name-only --diff-filter=ACM)
if [ -n "$files" ]; then
    echo "$files" | xargs "$BIN" scan
fi
`
	if err := os.WriteFile(hookPath, []byte(script), 0755); err != nil {
		return err
	}

	fmt.Println("Installed pre-commit hook at", hookPath)
	return nil
}
