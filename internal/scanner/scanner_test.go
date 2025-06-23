package scanner

import (
	"testing"

	"github.com/JohnnyCannelloni/gitguardian/internal/config"
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
			content:  "token = ghp_abcdefghijklmnopqrstuvwxyz1234567890AB", // Use letters to avoid hex match
			expected: 1,
			severity: "high",
		},
		{
			name:     "GitHub Classic Token",
			content:  "access_token = 1234567890abcdef1234567890abcdef12345678", // Pure hex, 40 chars
			expected: 1,
			severity: "high",
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
				for i, issue := range issues {
					t.Logf("Issue %d: Type=%s, Severity=%s, Rule=%s, Content=%s",
						i, issue.Type, issue.Severity, issue.Rule, issue.Content)
				}
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

func TestNew(t *testing.T) {
	cfg := config.DefaultConfig()
	scanner := New(cfg)

	if scanner == nil {
		t.Fatal("New() returned nil scanner")
	}

	if scanner.config == nil {
		t.Fatal("Scanner config is nil")
	}
}

func TestConfigInitialization(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if len(cfg.SecretPatterns) == 0 {
		t.Fatal("No secret patterns in default config")
	}

	// Test that patterns are compiled
	for i, pattern := range cfg.SecretPatterns {
		compiled := pattern.GetCompiledPattern()
		if compiled == nil {
			t.Errorf("Pattern %d (%s) is not compiled", i, pattern.Name)
		}
	}
}
