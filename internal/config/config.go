package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
)

// Config holds all configuration for GitGuardian
type Config struct {
	// General settings
	Verbose bool `json:"verbose"`

	// Secret scanning configuration
	SecretPatterns []SecretPattern `json:"secret_patterns"`
	Whitelist      []string        `json:"whitelist"`
	MaxFileSize    int64           `json:"max_file_size"` // in bytes

	// Dependency scanning
	DependencyAPIs DependencyConfig `json:"dependency_apis"`

	// Social engineering detection
	SocialEngineering SocialConfig `json:"social_engineering"`

	// Performance settings
	MaxConcurrency int `json:"max_concurrency"`
}

// SecretPattern defines a pattern to match secrets
type SecretPattern struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // low, medium, high, critical
	compiled    *regexp.Regexp
}

// DependencyConfig holds API configuration for vulnerability scanning
type DependencyConfig struct {
	OSVEnabled    bool   `json:"osv_enabled"`
	SnykAPIKey    string `json:"snyk_api_key"`
	GitHubToken   string `json:"github_token"`
	CacheEnabled  bool   `json:"cache_enabled"`
	CacheDuration int    `json:"cache_duration"` // hours
}

// SocialConfig holds social engineering detection settings
type SocialConfig struct {
	Enabled              bool     `json:"enabled"`
	SuspiciousKeywords   []string `json:"suspicious_keywords"`
	RequireJustification bool     `json:"require_justification"`
}

// Load loads configuration from file or returns default config
func Load(configPath string) (*Config, error) {
	cfg := DefaultConfig()

	if configPath == "" {
		// Try to find config in common locations
		possiblePaths := []string{
			".gitguardian.json",
			"gitguardian.json",
			filepath.Join(os.Getenv("HOME"), ".gitguardian.json"),
		}

		for _, path := range possiblePaths {
			if _, err := os.Stat(path); err == nil {
				configPath = path
				break
			}
		}
	}

	if configPath != "" {
		data, err := ioutil.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}

		// Compile patterns after loading from file
		if err := cfg.compilePatterns(); err != nil {
			return nil, fmt.Errorf("failed to compile patterns: %w", err)
		}
	}

	return cfg, nil
}

// DefaultConfig returns a default configuration with compiled patterns
func DefaultConfig() *Config {
	cfg := &Config{
		Verbose:        false,
		MaxFileSize:    10 * 1024 * 1024, // 10MB
		MaxConcurrency: 4,
		SecretPatterns: []SecretPattern{
			{
				Name:        "AWS Access Key",
				Pattern:     `AKIA[0-9A-Z]{16}`,
				Description: "Amazon Web Services Access Key",
				Severity:    "critical",
			},
			{
				Name:        "AWS Secret Key",
				Pattern:     `aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9+/]{40})["\']?`,
				Description: "Amazon Web Services Secret Key",
				Severity:    "critical",
			},
			{
				Name:        "GitHub Token",
				Pattern:     `ghp_[A-Za-z0-9]{36}`,
				Description: "GitHub Personal Access Token",
				Severity:    "high",
			},
			{
				Name:        "GitHub Classic Token",
				Pattern:     `[0-9a-f]{40}`,
				Description: "GitHub Classic Personal Access Token",
				Severity:    "high",
			},
			{
				Name:        "Slack Token",
				Pattern:     `xox[baprs]-[0-9a-zA-Z\-]+`,
				Description: "Slack API Token",
				Severity:    "high",
			},
			{
				Name:        "Generic API Key",
				Pattern:     `[Aa][Pp][Ii][_]?[Kk][Ee][Yy]\s*[:=]\s*["\']?([a-zA-Z0-9]{20,})["\']?`,
				Description: "Generic API Key Pattern",
				Severity:    "medium",
			},
			{
				Name:        "Generic Password",
				Pattern:     `[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?`,
				Description: "Generic Password Pattern",
				Severity:    "medium",
			},
			{
				Name:        "JWT Token",
				Pattern:     `eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*`,
				Description: "JSON Web Token",
				Severity:    "medium",
			},
			{
				Name:        "Private Key",
				Pattern:     `-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----`,
				Description: "Private Key",
				Severity:    "critical",
			},
		},
		Whitelist: []string{
			"example.com",
			"localhost",
			"127.0.0.1",
			"test",
			"demo",
			"sample",
		},
		DependencyAPIs: DependencyConfig{
			OSVEnabled:    true,
			CacheEnabled:  true,
			CacheDuration: 24,
		},
		SocialEngineering: SocialConfig{
			Enabled: true,
			SuspiciousKeywords: []string{
				"hack",
				"backdoor",
				"malware",
				"exploit",
				"bypass",
				"disable security",
				"remove check",
				"temporary fix",
				"todo: security",
			},
			RequireJustification: false,
		},
	}

	// IMPORTANT: Compile patterns immediately after creating config
	if err := cfg.compilePatterns(); err != nil {
		// If compilation fails, create a config with empty patterns rather than panic
		cfg.SecretPatterns = []SecretPattern{}
	}

	return cfg
}

// compilePatterns compiles all regex patterns
func (c *Config) compilePatterns() error {
	for i := range c.SecretPatterns {
		compiled, err := regexp.Compile(c.SecretPatterns[i].Pattern)
		if err != nil {
			return fmt.Errorf("failed to compile pattern '%s': %w", c.SecretPatterns[i].Name, err)
		}
		c.SecretPatterns[i].compiled = compiled
	}
	return nil
}

// GetCompiledPattern returns the compiled regex for a pattern
func (sp *SecretPattern) GetCompiledPattern() *regexp.Regexp {
	return sp.compiled
}

// Save saves the configuration to a file
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
