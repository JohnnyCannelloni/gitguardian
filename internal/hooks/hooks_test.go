package hooks

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstall(t *testing.T) {
	// Create temporary directory for fake git repository
	tempDir, err := ioutil.TempDir("", "gitguardian-hooks-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create .git directory structure
	gitDir := filepath.Join(tempDir, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	err = os.MkdirAll(hooksDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create .git/hooks directory: %v", err)
	}

	// Test installation
	err = Install(tempDir)
	if err != nil {
		t.Fatalf("Failed to install hooks: %v", err)
	}

	// Verify hooks were created
	expectedHooks := []string{"pre-commit", "pre-push", "commit-msg"}
	for _, hook := range expectedHooks {
		hookPath := filepath.Join(hooksDir, hook)

		// Check if file exists
		if _, err := os.Stat(hookPath); os.IsNotExist(err) {
			t.Errorf("Hook file not created: %s", hook)
			continue
		}

		// Check if file is executable
		info, err := os.Stat(hookPath)
		if err != nil {
			t.Errorf("Failed to stat hook file %s: %v", hook, err)
			continue
		}

		if info.Mode()&0111 == 0 {
			t.Errorf("Hook file %s is not executable", hook)
		}

		// Check if file contains GitGuardian signature
		content, err := ioutil.ReadFile(hookPath)
		if err != nil {
			t.Errorf("Failed to read hook file %s: %v", hook, err)
			continue
		}

		if !strings.Contains(string(content), "GitGuardian") {
			t.Errorf("Hook file %s does not contain GitGuardian signature", hook)
		}
	}
}

func TestInstall_NotGitRepository(t *testing.T) {
	// Create temporary directory without .git
	tempDir, err := ioutil.TempDir("", "gitguardian-hooks-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test installation should fail
	err = Install(tempDir)
	if err == nil {
		t.Error("Expected error when installing hooks in non-git repository")
	}

	if !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("Expected 'not a git repository' error, got: %v", err)
	}
}

func TestInstall_BackupExistingHooks(t *testing.T) {
	// Create temporary directory for fake git repository
	tempDir, err := ioutil.TempDir("", "gitguardian-hooks-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create .git directory structure
	gitDir := filepath.Join(tempDir, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	err = os.MkdirAll(hooksDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create .git/hooks directory: %v", err)
	}

	// Create existing hook
	existingHookContent := "#!/bin/sh\necho 'existing hook'"
	existingHookPath := filepath.Join(hooksDir, "pre-commit")
	err = ioutil.WriteFile(existingHookPath, []byte(existingHookContent), 0755)
	if err != nil {
		t.Fatalf("Failed to create existing hook: %v", err)
	}

	// Install GitGuardian hooks
	err = Install(tempDir)
	if err != nil {
		t.Fatalf("Failed to install hooks: %v", err)
	}

	// Check if backup was created
	backupPath := existingHookPath + ".backup"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		t.Error("Existing hook was not backed up")
	} else {
		// Verify backup content
		backupContent, err := ioutil.ReadFile(backupPath)
		if err != nil {
			t.Errorf("Failed to read backup file: %v", err)
		} else if string(backupContent) != existingHookContent {
			t.Error("Backup content does not match original hook")
		}
	}

	// Check if new hook was installed
	newContent, err := ioutil.ReadFile(existingHookPath)
	if err != nil {
		t.Fatalf("Failed to read new hook: %v", err)
	}

	if !strings.Contains(string(newContent), "GitGuardian") {
		t.Error("New hook does not contain GitGuardian signature")
	}
}

func TestUninstall(t *testing.T) {
	// Create temporary directory for fake git repository
	tempDir, err := ioutil.TempDir("", "gitguardian-hooks-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create .git directory structure
	gitDir := filepath.Join(tempDir, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	err = os.MkdirAll(hooksDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create .git/hooks directory: %v", err)
	}

	// Install hooks first
	err = Install(tempDir)
	if err != nil {
		t.Fatalf("Failed to install hooks: %v", err)
	}

	// Verify hooks exist
	preCommitPath := filepath.Join(hooksDir, "pre-commit")
	if _, err := os.Stat(preCommitPath); os.IsNotExist(err) {
		t.Fatal("Pre-commit hook was not installed")
	}

	// Uninstall hooks
	err = Uninstall(tempDir)
	if err != nil {
		t.Fatalf("Failed to uninstall hooks: %v", err)
	}

	// Verify hooks were removed
	if _, err := os.Stat(preCommitPath); !os.IsNotExist(err) {
		t.Error("Pre-commit hook was not removed")
	}
}

func TestIsGitRepository(t *testing.T) {
	// Create temporary directory without .git
	tempDir, err := ioutil.TempDir("", "gitguardian-hooks-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test non-git directory
	if IsGitRepository(tempDir) {
		t.Error("Expected false for non-git directory")
	}

	// Create .git directory
	gitDir := filepath.Join(tempDir, ".git")
	err = os.MkdirAll(gitDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create .git directory: %v", err)
	}

	// Test git directory
	if !IsGitRepository(tempDir) {
		t.Error("Expected true for git directory")
	}
}

func TestGetRepositoryRoot(t *testing.T) {
	// Skip this test if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git command not available")
	}

	// Create temporary directory
	tempDir, err := ioutil.TempDir("", "gitguardian-hooks-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize git repository
	cmd := exec.Command("git", "init")
	cmd.Dir = tempDir
	err = cmd.Run()
	if err != nil {
		t.Skip("Failed to initialize git repository - git may not be configured")
	}

	// Test getting repository root
	root, err := GetRepositoryRoot(tempDir)
	if err != nil {
		t.Fatalf("Failed to get repository root: %v", err)
	}

	// The root should be the temp directory (or its absolute path)
	if !strings.HasSuffix(root, filepath.Base(tempDir)) && root != tempDir {
		t.Errorf("Expected repository root to end with %s, got %s", filepath.Base(tempDir), root)
	}

	// Test with non-git directory
	nonGitDir, err := ioutil.TempDir("", "non-git-dir")
	if err != nil {
		t.Fatalf("Failed to create non-git temp dir: %v", err)
	}
	defer os.RemoveAll(nonGitDir)

	_, err = GetRepositoryRoot(nonGitDir)
	if err == nil {
		t.Error("Expected error for non-git directory")
	}
}

func TestCheckHooksInstalled(t *testing.T) {
	// Create temporary directory for fake git repository
	tempDir, err := ioutil.TempDir("", "gitguardian-hooks-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create .git directory structure
	gitDir := filepath.Join(tempDir, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	err = os.MkdirAll(hooksDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create .git/hooks directory: %v", err)
	}

	// Check status before installation
	status, err := CheckHooksInstalled(tempDir)
	if err != nil {
		t.Fatalf("Failed to check hooks status: %v", err)
	}

	expectedHooks := []string{"pre-commit", "pre-push", "commit-msg"}
	for _, hook := range expectedHooks {
		if status[hook] {
			t.Errorf("Hook %s should not be installed yet", hook)
		}
	}

	// Install hooks
	err = Install(tempDir)
	if err != nil {
		t.Fatalf("Failed to install hooks: %v", err)
	}

	// Check status after installation
	status, err = CheckHooksInstalled(tempDir)
	if err != nil {
		t.Fatalf("Failed to check hooks status after installation: %v", err)
	}

	for _, hook := range expectedHooks {
		if !status[hook] {
			t.Errorf("Hook %s should be installed", hook)
		}
	}
}

func TestGenerateHookScript(t *testing.T) {
	tests := []struct {
		hookType   string
		binaryPath string
		expected   []string // Expected content fragments
	}{
		{
			hookType:   "pre-commit",
			binaryPath: "",
			expected:   []string{"GitGuardian pre-commit hook", "GITGUARDIAN_BIN=\"gitguardian\""},
		},
		{
			hookType:   "pre-push",
			binaryPath: "/custom/path/gitguardian",
			expected:   []string{"GitGuardian pre-push hook", "GITGUARDIAN_BIN=\"/custom/path/gitguardian\""},
		},
		{
			hookType:   "commit-msg",
			binaryPath: "",
			expected:   []string{"GitGuardian commit-msg hook", "GITGUARDIAN_BIN=\"gitguardian\""},
		},
		{
			hookType:   "invalid",
			binaryPath: "",
			expected:   nil, // Should return empty string
		},
	}

	for _, tt := range tests {
		t.Run(tt.hookType, func(t *testing.T) {
			script := GenerateHookScript(tt.hookType, tt.binaryPath)

			if tt.expected == nil {
				if script != "" {
					t.Errorf("Expected empty script for invalid hook type, got: %s", script)
				}
				return
			}

			if script == "" {
				t.Error("Expected non-empty script")
				return
			}

			for _, expected := range tt.expected {
				if !strings.Contains(script, expected) {
					t.Errorf("Expected script to contain '%s', got: %s", expected, script)
				}
			}
		})
	}
}

func TestGetChangedFiles(t *testing.T) {
	// Skip this test if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git command not available")
	}

	// Create temporary directory
	tempDir, err := ioutil.TempDir("", "gitguardian-hooks-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize git repository
	cmd := exec.Command("git", "init")
	cmd.Dir = tempDir
	err = cmd.Run()
	if err != nil {
		t.Skip("Failed to initialize git repository")
	}

	// Configure git user (required for commits)
	cmd = exec.Command("git", "config", "user.email", "test@example.com")
	cmd.Dir = tempDir
	cmd.Run()

	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tempDir
	cmd.Run()

	// Create and stage a file
	testFile := filepath.Join(tempDir, "test.txt")
	err = ioutil.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	cmd = exec.Command("git", "add", "test.txt")
	cmd.Dir = tempDir
	err = cmd.Run()
	if err != nil {
		t.Skip("Failed to stage file")
	}

	// Save current directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	defer os.Chdir(originalDir)

	// Change to temp directory for git commands
	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	// Test getting staged files
	files, err := GetChangedFiles("pre-commit")
	if err != nil {
		t.Fatalf("Failed to get changed files: %v", err)
	}

	// Should include our staged file
	found := false
	for _, file := range files {
		if file == "test.txt" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected to find 'test.txt' in changed files, got: %v", files)
	}

	// Test unsupported operation
	_, err = GetChangedFiles("unsupported")
	if err == nil {
		t.Error("Expected error for unsupported operation")
	}
}
