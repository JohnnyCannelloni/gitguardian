package scanner

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yourusername/gitguardian/internal/config"
)

func TestScanner_ScanSecrets(t *testing.T) {
	cfg := config.DefaultConfig()
	scanner := New(cfg)

	tests := []struct {
		name     string
		content  string
		expected int
		severity string
	}{
		{
			name:     "AWS Access Key",
			content:  "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
			expected: 1,
			severity: "critical",
		},
		{
			name:     "GitHub Token",
			content:  "token = ghp_1234567890abcdef1234567890abcdef12345678",
			expected: 1,
			severity: "high",
		},
		{
			name:     "Generic API Key",
			content:  "api_key = sk_test_1234567890abcdef",
			expected: 1,
			severity: "medium",
		},
		{
			name:     "JWT Token",
			content:  "jwt = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: 1,
			severity: "medium",
		},
		{
			name:     "Private Key",
			content:  "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
			expected: 1,
			severity: "critical",
		},
		{
			name:     "No secrets",
			content:  "This is just normal text with no secrets",
			expected: 0,
		},
		{
			name:     "Whitelisted content",
			content:  "example.com test localhost",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := scanner.scanSecrets("test.txt", tt.content)

			if len(issues) != tt.expected {
				t.Errorf("Expected %d issues, got %d", tt.expected, len(issues))
			}

			if tt.expected > 0 && len(issues) > 0 {
				if issues[0].Severity != tt.severity {
					t.Errorf("Expected severity %s, got %s", tt.severity, issues[0].Severity)
				}
				if issues[0].Type != "secret" {
					t.Errorf("Expected type 'secret', got %s", issues[0].Type)
				}
			}
		})
	}
}

func TestScanner_ScanSocialEngineering(t *testing.T) {
	cfg := config.DefaultConfig()
	scanner := New(cfg)

	tests := []struct {
		name     string
		content  string
		expected int
	}{
		{
			name:     "Suspicious hack keyword",
			content:  "// TODO: hack around this security issue",
			expected: 1,
		},
		{
			name:     "Backdoor mention",
			content:  "Adding backdoor for testing",
			expected: 1,
		},
		{
			name:     "Bypass security",
			content:  "bypass security check temporarily",
			expected: 1,
		},
		{
			name:     "Normal comment",
			content:  "This is a normal comment about functionality",
			expected: 0,
		},
		{
			name:     "Multiple suspicious keywords",
			content:  "hack the system and bypass security",
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := scanner.scanSocialEngineering("test.txt", tt.content)

			if len(issues) != tt.expected {
				t.Errorf("Expected %d issues, got %d", tt.expected, len(issues))
			}

			for _, issue := range issues {
				if issue.Type != "social" {
					t.Errorf("Expected type 'social', got %s", issue.Type)
				}
				if issue.Severity != "medium" {
					t.Errorf("Expected severity 'medium', got %s", issue.Severity)
				}
			}
		})
	}
}

func TestScanner_ScanPath(t *testing.T) {
	// Create temporary directory structure
	tempDir, err := ioutil.TempDir("", "gitguardian-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	testFiles := map[string]string{
		"secrets.js": `
			const config = {
				awsKey: "AKIAIOSFODNN7EXAMPLE",
				githubToken: "ghp_1234567890abcdef1234567890abcdef12345678"
			};
		`,
		"package.json": `{
			"dependencies": {
				"lodash": "4.17.20",
				"express": "4.17.1"
			}
		}`,
		"safe.txt":   "This file contains no secrets",
		"binary.bin": string([]byte{0x00, 0x01, 0x02, 0x03}), // Binary file
	}

	for filename, content := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		if err := ioutil.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	// Create subdirectory with ignored directory
	nodeModulesDir := filepath.Join(tempDir, "node_modules")
	if err := os.MkdirAll(nodeModulesDir, 0755); err != nil {
		t.Fatalf("Failed to create node_modules dir: %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(nodeModulesDir, "secret.js"), []byte("AKIATEST"), 0644); err != nil {
		t.Fatalf("Failed to create file in node_modules: %v", err)
	}

	cfg := config.DefaultConfig()
	scanner := New(cfg)

	// Test scanning
	results, err := scanner.ScanPath(tempDir, ScanTypeAll)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Verify results
	if results.FilesScanned == 0 {
		t.Error("Expected files to be scanned")
	}

	// Should find secrets in secrets.js
	secretIssues := 0
	for _, issue := range results.Issues {
		if issue.Type == "secret" {
			secretIssues++
		}
	}

	if secretIssues == 0 {
		t.Error("Expected to find secret issues")
	}

	// Verify summary
	if results.Summary.Total == 0 {
		t.Error("Expected summary to show total issues")
	}

	// Test JSON output
	var jsonOutput strings.Builder
	if err := results.OutputJSON(&jsonOutput); err != nil {
		t.Errorf("Failed to output JSON: %v", err)
	}

	var jsonResult Results
	if err := json.Unmarshal([]byte(jsonOutput.String()), &jsonResult); err != nil {
		t.Errorf("Failed to parse JSON output: %v", err)
	}

	// Test text output
	var textOutput strings.Builder
	if err := results.OutputText(&textOutput); err != nil {
		t.Errorf("Failed to output text: %v", err)
	}

	textStr := textOutput.String()
	if !strings.Contains(textStr, "GitGuardian Security Scan Results") {
		t.Error("Expected text output to contain header")
	}
}

func TestScanner_FileFiltering(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		{"test.go", true},
		{"config.json", true},
		{"README.md", true},
		{"Dockerfile", true},
		{"package.json", true},
		{"requirements.txt", true},
		{"binary.exe", false},
		{"image.png", false},
		{"document.pdf", false},
		{".gitignore", true},
		{"script.sh", true},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result := shouldScanFile(tt.filename)
			if result != tt.expected {
				t.Errorf("shouldScanFile(%s) = %v, expected %v", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestScanner_DirectoryFiltering(t *testing.T) {
	tests := []struct {
		dirname  string
		expected bool
	}{
		{"src", false},
		{"docs", false},
		{".git", true},
		{"node_modules", true},
		{"vendor", true},
		{".venv", true},
		{"build", true},
		{"target", true},
		{".idea", true},
	}

	for _, tt := range tests {
		t.Run(tt.dirname, func(t *testing.T) {
			result := shouldSkipDir(tt.dirname)
			if result != tt.expected {
				t.Errorf("shouldSkipDir(%s) = %v, expected %v", tt.dirname, result, tt.expected)
			}
		})
	}
}

func TestScanner_MaskSecret(t *testing.T) {
	scanner := New(config.DefaultConfig())

	tests := []struct {
		input    string
		expected string
	}{
		{"short", "*****"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA************MPLE"},
		{"verylongsecretkeythatshouldbeproperlyhidden", "very********************************dden"},
		{"", ""},
		{"test1234", "********"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := scanner.maskSecret(tt.input)
			if result != tt.expected {
				t.Errorf("maskSecret(%s) = %s, expected %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestScanner_Whitelist(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Whitelist = []string{"example.com", "test", "localhost"}
	scanner := New(cfg)

	tests := []struct {
		value    string
		expected bool
	}{
		{"example.com", true},
		{"test_value", true},
		{"localhost:3000", true},
		{"production_secret", false},
		{"real_api_key", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			result := scanner.isWhitelisted(tt.value)
			if result != tt.expected {
				t.Errorf("isWhitelisted(%s) = %v, expected %v", tt.value, result, tt.expected)
			}
		})
	}
}

func TestScanner_BinaryDetection(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Text file",
			data:     []byte("This is a normal text file"),
			expected: false,
		},
		{
			name:     "Binary file with null bytes",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0x04},
			expected: true,
		},
		{
			name:     "UTF-8 text",
			data:     []byte("Hello 世界"),
			expected: false,
		},
		{
			name:     "JSON file",
			data:     []byte(`{"key": "value"}`),
			expected: false,
		},
		{
			name:     "Mixed with null at end",
			data:     append([]byte("Normal text"), 0x00),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isBinary(tt.data)
			if result != tt.expected {
				t.Errorf("isBinary() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestScanner_DependencyFileDetection(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		{"package.json", true},
		{"package-lock.json", true},
		{"go.mod", true},
		{"go.sum", true},
		{"requirements.txt", true},
		{"Pipfile", true},
		{"Gemfile", true},
		{"composer.json", true},
		{"pom.xml", true},
		{"Cargo.toml", true},
		{"random.txt", false},
		{"config.json", false},
		{"README.md", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result := isDependencyFile(tt.filename)
			if result != tt.expected {
				t.Errorf("isDependencyFile(%s) = %v, expected %v", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestResults_HasIssues(t *testing.T) {
	tests := []struct {
		name     string
		issues   []Issue
		expected bool
	}{
		{
			name:     "No issues",
			issues:   []Issue{},
			expected: false,
		},
		{
			name: "Has issues",
			issues: []Issue{
				{Type: "secret", Severity: "high"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := &Results{Issues: tt.issues}
			if results.HasIssues() != tt.expected {
				t.Errorf("HasIssues() = %v, expected %v", results.HasIssues(), tt.expected)
			}
		})
	}
}

func BenchmarkScanner_ScanSecrets(b *testing.B) {
	cfg := config.DefaultConfig()
	scanner := New(cfg)

	content := `
		const config = {
			awsKey: "AKIAIOSFODNN7EXAMPLE",
			githubToken: "ghp_1234567890abcdef1234567890abcdef12345678",
			database: "mongodb://user:pass@localhost:27017/db",
			apiKey: "sk_test_1234567890abcdef1234567890abcdef",
			jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		};
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.scanSecrets("benchmark.js", content)
	}
}

func BenchmarkScanner_ScanPath(b *testing.B) {
	// Create temp directory with test files
	tempDir, err := ioutil.TempDir("", "gitguardian-benchmark")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create multiple test files
	for i := 0; i < 10; i++ {
		content := `
			const secrets = {
				key1: "AKIAIOSFODNN7EXAMPLE",
				key2: "ghp_1234567890abcdef1234567890abcdef12345678"
			};
		`
		filename := filepath.Join(tempDir, "test"+string(rune(i))+"file.js")
		if err := ioutil.WriteFile(filename, []byte(content), 0644); err != nil {
			b.Fatalf("Failed to create test file: %v", err)
		}
	}

	cfg := config.DefaultConfig()
	scanner := New(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.ScanPath(tempDir, ScanTypeSecrets)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}
