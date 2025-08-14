package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	preCommitHook = `#!/bin/sh
# GitGuardian pre-commit hook
# this hook runs security scanning before each commit

# get the binary path
GITGUARDIAN_BIN="gitguardian"

# check if gitguardian is in PATH
if ! command -v $GITGUARDIAN_BIN > /dev/null 2>&1; then
    echo "Warning: gitguardian binary not found in PATH"
    echo "Please ensure GitGuardian is installed and available in your PATH"
    exit 0
fi

# get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    echo "No staged files to scan"
    exit 0
fi

echo "🔍 Running GitGuardian security scan on staged files..."

# create temporary directory for staged files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# copy staged files to temp directory
for file in $STAGED_FILES; do
    if [ -f "$file" ]; then
        mkdir -p "$TEMP_DIR/$(dirname "$file")"
        git show ":$file" > "$TEMP_DIR/$file" 2>/dev/null || cp "$file" "$TEMP_DIR/$file"
    fi
done

# run scan on temp directory
$GITGUARDIAN_BIN -path "$TEMP_DIR" -format text

SCAN_RESULT=$?

if [ $SCAN_RESULT -ne 0 ]; then
    echo ""
    echo "❌ Security issues found in staged files!"
    echo "Please fix the issues above before committing."
    echo ""
    echo "To bypass this check (NOT RECOMMENDED), use:"
    echo "  git commit --no-verify"
    echo ""
    exit 1
fi

echo "✅ No security issues found in staged files"
exit 0
`

	prePushHook = `#!/bin/sh
# GitGuardian pre-push hook
# this hook runs security scanning before pushing commits

# get the binary path
GITGUARDIAN_BIN="gitguardian"

# check if gitguardian is in PATH
if ! command -v $GITGUARDIAN_BIN > /dev/null 2>&1; then
    echo "Warning: gitguardian binary not found in PATH"
    echo "Please ensure GitGuardian is installed and available in your PATH"
    exit 0
fi

remote="$1"
url="$2"

z40=0000000000000000000000000000000000000000

while read local_ref local_sha remote_ref remote_sha
do
    if [ "$local_sha" = $z40 ]; then
        # Handle delete
        :
    else
        if [ "$remote_sha" = $z40 ]; then
            # new branch
            range="$local_sha"
        else
            # update to existing branch
            range="$remote_sha..$local_sha"
        fi

        # get list of files changed in this push
        CHANGED_FILES=$(git diff --name-only $range 2>/dev/null)

        if [ -n "$CHANGED_FILES" ]; then
            echo "🔍 Running GitGuardian security scan on changed files..."
            
            # create temp directory
            TEMP_DIR=$(mktemp -d)
            trap "rm -rf $TEMP_DIR" EXIT

            # copy changed files to temp directory
            for file in $CHANGED_FILES; do
                if [ -f "$file" ]; then
                    mkdir -p "$TEMP_DIR/$(dirname "$file")"
                    cp "$file" "$TEMP_DIR/$file"
                fi
            done

            # run scan
            $GITGUARDIAN_BIN -path "$TEMP_DIR" -format text

            SCAN_RESULT=$?

            if [ $SCAN_RESULT -ne 0 ]; then
                echo ""
                echo "❌ Security issues found in files being pushed!"
                echo "Please fix the issues above before pushing."
                echo ""
                echo "To bypass this check (NOT RECOMMENDED), use:"
                echo "  git push --no-verify"
                echo ""
                exit 1
            fi

            echo "✅ No security issues found in changed files"
        fi
    fi
done

exit 0
`

	commitMsgHook = `#!/bin/sh
# GitGuardian commit-msg hook
# this hook checks commit messages for suspicious words

# get the binary path
GITGUARDIAN_BIN="gitguardian"

# check if gitguardian is in PATH
if ! command -v $GITGUARDIAN_BIN > /dev/null 2>&1; then
    exit 0
fi

# read the commit message
COMMIT_MSG_FILE="$1"
COMMIT_MSG=$(cat "$COMMIT_MSG_FILE")

# check for suspicious words in message
SUSPICIOUS_KEYWORDS="hack backdoor malware exploit bypass disable.security remove.check temporary.fix todo.security"

for keyword in $SUSPICIOUS_KEYWORDS; do
    # replace dots with spaces for pattern matching
    pattern=$(echo "$keyword" | sed 's/\./ /g')
    if echo "$COMMIT_MSG" | grep -qi "$pattern"; then
        echo "⚠️  Warning: Suspicious keyword detected in commit message: '$pattern'"
        echo "Commit message: $COMMIT_MSG"
        echo ""
        echo "Please review your commit message for security implications."
        echo "If this is intentional, you can proceed or use --no-verify to bypass."
        echo ""
        read -p "Continue with this commit message? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
done

exit 0
`
)

// installs hooks in the specified repo
func Install(repoPath string) error {
	// ensure we're in a git repo
	gitDir := filepath.Join(repoPath, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return fmt.Errorf("not a git repository: %s", repoPath)
	}

	hooksDir := filepath.Join(gitDir, "hooks")

	// create hooks directory if it doesn't exist
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create hooks directory: %w", err)
	}

	if err := installHook(hooksDir, "pre-commit", preCommitHook); err != nil {
		return fmt.Errorf("failed to install pre-commit hook: %w", err)
	}

	if err := installHook(hooksDir, "pre-push", prePushHook); err != nil {
		return fmt.Errorf("failed to install pre-push hook: %w", err)
	}

	if err := installHook(hooksDir, "commit-msg", commitMsgHook); err != nil {
		return fmt.Errorf("failed to install commit-msg hook: %w", err)
	}

	fmt.Printf("✅ GitGuardian hooks installed successfully in %s\n", repoPath)
	fmt.Println("\nInstalled hooks:")
	fmt.Println("  - pre-commit: Scans staged files before commit")
	fmt.Println("  - pre-push: Scans changed files before push")
	fmt.Println("  - commit-msg: Checks commit messages for suspicious keywords")
	fmt.Println("\nTo bypass hooks when needed, use --no-verify flag")

	return nil
}

// removes GitGuardian hooks from the repo
func Uninstall(repoPath string) error {
	gitDir := filepath.Join(repoPath, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return fmt.Errorf("not a git repository: %s", repoPath)
	}

	hooksDir := filepath.Join(gitDir, "hooks")
	hooks := []string{"pre-commit", "pre-push", "commit-msg"}

	for _, hook := range hooks {
		hookPath := filepath.Join(hooksDir, hook)

		// check if it's our hook
		if content, err := os.ReadFile(hookPath); err == nil {
			if strings.Contains(string(content), "GitGuardian") {
				if err := os.Remove(hookPath); err != nil {
					fmt.Printf("Warning: failed to remove %s hook: %v\n", hook, err)
				} else {
					fmt.Printf("✅ Removed %s hook\n", hook)
				}
			}
		}
	}

	return nil
}

// installs a single hook file
func installHook(hooksDir, hookName, hookContent string) error {
	hookPath := filepath.Join(hooksDir, hookName)

	// check if hook already exists
	if _, err := os.Stat(hookPath); err == nil {
		// read existing hook
		existing, err := os.ReadFile(hookPath)
		if err == nil && strings.Contains(string(existing), "GitGuardian") {
			fmt.Printf("✅ %s hook already installed\n", hookName)
			return nil
		}

		// backup existing hook
		backupPath := hookPath + ".backup"
		if err := os.Rename(hookPath, backupPath); err != nil {
			return fmt.Errorf("failed to backup existing hook: %w", err)
		}
		fmt.Printf("📁 Backed up existing %s hook to %s\n", hookName, backupPath)
	}

	// write the hook
	if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
		return fmt.Errorf("failed to write hook file: %w", err)
	}

	fmt.Printf("✅ Installed %s hook\n", hookName)
	return nil
}

// returns a list of changed files for different Git operations
func GetChangedFiles(operation string) ([]string, error) {
	var cmd *exec.Cmd

	switch operation {
	case "pre-commit":
		cmd = exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACM")
	case "pre-push":
		cmd = exec.Command("git", "diff", "--name-only", "HEAD")
	default:
		return nil, fmt.Errorf("unsupported operation: %s", operation)
	}

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get changed files: %w", err)
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")

	// filter out empty lines
	var result []string
	for _, file := range files {
		if file != "" {
			result = append(result, file)
		}
	}

	return result, nil
}

// checks if the given path is a git repo
func IsGitRepository(path string) bool {
	gitDir := filepath.Join(path, ".git")
	if info, err := os.Stat(gitDir); err == nil {
		return info.IsDir()
	}

	// check if we're inside a git repo
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	cmd.Dir = path
	_, err := cmd.Output()
	return err == nil
}

// returns the root directory of the git repo
func GetRepositoryRoot(path string) (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = path

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not in a git repository")
	}

	return strings.TrimSpace(string(output)), nil
}

// checks if hooks are installed
func CheckHooksInstalled(repoPath string) (map[string]bool, error) {
	status := make(map[string]bool)
	hooks := []string{"pre-commit", "pre-push", "commit-msg"}

	gitDir := filepath.Join(repoPath, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")

	for _, hook := range hooks {
		hookPath := filepath.Join(hooksDir, hook)

		if content, err := os.ReadFile(hookPath); err == nil {
			status[hook] = strings.Contains(string(content), "GitGuardian")
		} else {
			status[hook] = false
		}
	}

	return status, nil
}

// generates a hook script for a specific platform
func GenerateHookScript(hookType, binaryPath string) string {
	var script string

	switch hookType {
	case "pre-commit":
		script = preCommitHook
	case "pre-push":
		script = prePushHook
	case "commit-msg":
		script = commitMsgHook
	default:
		return ""
	}

	// replace binary path if specified
	if binaryPath != "" {
		script = strings.Replace(script, `GITGUARDIAN_BIN="gitguardian"`,
			fmt.Sprintf(`GITGUARDIAN_BIN="%s"`, binaryPath), 1)
	}

	// adjust for windows if needed
	if runtime.GOOS == "windows" {
		// Convert to Windows batch script
		script = convertToWindowsBatch(script)
	}

	return script
}

// converts shell script to Windows batch script
func convertToWindowsBatch(shellScript string) string {
	batchScript := `@echo off
REM GitGuardian Windows hook
REM This is a simplified Windows version of the hook

set GITGUARDIAN_BIN=gitguardian.exe

where %GITGUARDIAN_BIN% >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Warning: gitguardian.exe not found in PATH
    echo Please ensure GitGuardian is installed and available in your PATH
    exit /b 0
)

echo Running GitGuardian security scan...
%GITGUARDIAN_BIN% -path . -format text

if %ERRORLEVEL% neq 0 (
    echo.
    echo Security issues found!
    echo Please fix the issues above before proceeding.
    echo.
    exit /b 1
)

echo No security issues found
exit /b 0
`
	return batchScript
}
