package config

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestConfig_Load(t *testing.T) {
	// Test loading default config
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	if cfg == nil {
		t.Fatal("Config should not be nil")
	}

	// Verify default values
	if cfg.MaxFileSize != 10*1024*1024 {
		t.Errorf("Expected MaxFileSize to be 10MB, got %d", cfg.MaxFileSize)
	}

	if cfg.MaxConcurrency != 4 {
		t.Errorf("Expected MaxConcurrency to be 4, got %d", cfg.MaxConcurrency)
	}

	if len(cfg.SecretPatterns) == 0 {
		t.Error("Expected default secret patterns to be loaded")
	}
}

func TestConfig_LoadFromFile(t *testing.T) {
	// Create temporary config file
	tempDir, err := ioutil.TempDir("", "gitguardian-config-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configContent := `{
		"verbose": true,
		"max_file_size": 5242880,
		"max_concurrency": 8,
		"secret_patterns": [
			{
				"name": "Test Pattern",
				"pattern": "test[0-9]+",
				"description": "Test pattern description",
				"severity": "low"
			}
		],
		"whitelist": ["test.com"],
		"dependency_apis": {
			"osv_enabled": false,
			"cache_enabled": false
		},
		"social_engineering": {
			"enabled": false
		}
	}`

	configPath := filepath.Join(tempDir, "test-config.json")
	err = ioutil.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load config from file
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config from file: %v", err)
	}

	// Verify loaded values
	if !cfg.Verbose {
		t.Error("Expected Verbose to be true")
	}

	if cfg.MaxFileSize != 5242880 {
		t.Errorf("Expected MaxFileSize to be 5MB, got %d", cfg.MaxFileSize)
	}

	if cfg.MaxConcurrency != 8 {
		t.Errorf("Expected MaxConcurrency to be 8, got %d", cfg.MaxConcurrency)
	}

	if len(cfg.SecretPatterns) != 1 {
		t.Errorf("Expected 1 secret pattern, got %d", len(cfg.SecretPatterns))
	}

	if cfg.SecretPatterns[0].Name != "Test Pattern" {
		t.Errorf("Expected pattern name 'Test Pattern', got %s", cfg.SecretPatterns[0].Name)
	}

	if len(cfg.Whitelist) != 1 || cfg.Whitelist[0] != "test.com" {
		t.Errorf("Expected whitelist to contain 'test.com', got %v", cfg.Whitelist)
	}

	if cfg.DependencyAPIs.OSVEnabled {
		t.Error("Expected OSVEnabled to be false")
	}

	if cfg.SocialEngineering.Enabled {
		t.Error("Expected SocialEngineering.Enabled to be false")
	}
}

func TestConfig_LoadInvalidFile(t *testing.T) {
	// Test loading non-existent file
	_, err := Load("/non/existent/file.json")
	if err == nil {
		t.Error("Expected error when loading non-existent file")
	}

	// Test loading invalid JSON
	tempDir, err := ioutil.TempDir("", "gitguardian-config-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	invalidConfigPath := filepath.Join(tempDir, "invalid.json")
	err = ioutil.WriteFile(invalidConfigPath, []byte("invalid json content"), 0644)
	if err != nil {
		t.Fatalf("Failed to write invalid config file: %v", err)
	}

	_, err = Load(invalidConfigPath)
	if err == nil {
		t.Error("Expected error when loading invalid JSON file")
	}
}

func TestConfig_Save(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Verbose = true
	cfg.MaxConcurrency = 8

	tempDir, err := ioutil.TempDir("", "gitguardian-config-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "saved-config.json")
	err = cfg.Save(configPath)
	if err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file was not created")
	}

	// Load and verify saved config
	loadedCfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}

	if !loadedCfg.Verbose {
		t.Error("Expected loaded config to have Verbose=true")
	}

	if loadedCfg.MaxConcurrency != 8 {
		t.Errorf("Expected loaded config to have MaxConcurrency=8, got %d", loadedCfg.MaxConcurrency)
	}
}

func TestSecretPattern_CompilePatterns(t *testing.T) {
	cfg := &Config{
		SecretPatterns: []SecretPattern{
			{
				Name:        "Valid Pattern",
				Pattern:     `test[0-9]+`,
				Description: "Test pattern",
				Severity:    "low",
			},
			{
				Name:        "Invalid Pattern",
				Pattern:     `[unclosed`,
				Description: "Invalid regex",
				Severity:    "medium",
			},
		},
	}

	err := cfg.compilePatterns()
	if err == nil {
		t.Error("Expected error when compiling invalid regex pattern")
	}

	// Test with valid patterns only
	cfg.SecretPatterns = []SecretPattern{
		{
			Name:        "Valid Pattern",
			Pattern:     `test[0-9]+`,
			Description: "Test pattern",
			Severity:    "low",
		},
	}

	err = cfg.compilePatterns()
	if err != nil {
		t.Errorf("Failed to compile valid patterns: %v", err)
	}

	// Test that pattern was compiled
	compiled := cfg.SecretPatterns[0].GetCompiledPattern()
	if compiled == nil {
		t.Error("Expected compiled pattern to not be nil")
	}

	// Test pattern matching
	matches := compiled.FindString("test123")
	if matches != "test123" {
		t.Errorf("Expected pattern to match 'test123', got '%s'", matches)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Test that default config is valid
	if cfg == nil {
		t.Fatal("Default config should not be nil")
	}

	// Test default values
	expectedDefaults := map[string]interface{}{
		"verbose":        false,
		"maxFileSize":    int64(10 * 1024 * 1024),
		"maxConcurrency": 4,
		"osvEnabled":     true,
		"cacheEnabled":   true,
		"cacheDuration":  24,
		"socialEnabled":  true,
	}

	if cfg.Verbose != expectedDefaults["verbose"].(bool) {
		t.Errorf("Expected Verbose=%v, got %v", expectedDefaults["verbose"], cfg.Verbose)
	}

	if cfg.MaxFileSize != expectedDefaults["maxFileSize"].(int64) {
		t.Errorf("Expected MaxFileSize=%v, got %v", expectedDefaults["maxFileSize"], cfg.MaxFileSize)
	}

	if cfg.MaxConcurrency != expectedDefaults["maxConcurrency"].(int) {
		t.Errorf("Expected MaxConcurrency=%v, got %v", expectedDefaults["maxConcurrency"], cfg.MaxConcurrency)
	}

	if cfg.DependencyAPIs.OSVEnabled != expectedDefaults["osvEnabled"].(bool) {
		t.Errorf("Expected OSVEnabled=%v, got %v", expectedDefaults["osvEnabled"], cfg.DependencyAPIs.OSVEnabled)
	}

	if cfg.DependencyAPIs.CacheEnabled != expectedDefaults["cacheEnabled"].(bool) {
		t.Errorf("Expected CacheEnabled=%v, got %v", expectedDefaults["cacheEnabled"], cfg.DependencyAPIs.CacheEnabled)
	}

	if cfg.DependencyAPIs.CacheDuration != expectedDefaults["cacheDuration"].(int) {
		t.Errorf("Expected CacheDuration=%v, got %v", expectedDefaults["cacheDuration"], cfg.DependencyAPIs.CacheDuration)
	}

	if cfg.SocialEngineering.Enabled != expectedDefaults["socialEnabled"].(bool) {
		t.Errorf("Expected SocialEngineering.Enabled=%v, got %v", expectedDefaults["socialEnabled"], cfg.SocialEngineering.Enabled)
	}

	// Test that secret patterns are included
	if len(cfg.SecretPatterns) == 0 {
		t.Error("Expected default config to include secret patterns")
	}

	// Test that whitelist is included
	if len(cfg.Whitelist) == 0 {
		t.Error("Expected default config to include whitelist entries")
	}

	// Test that social engineering keywords are included
	if len(cfg.SocialEngineering.SuspiciousKeywords) == 0 {
		t.Error("Expected default config to include social engineering keywords")
	}

	// Test that patterns can be compiled
	err := cfg.compilePatterns()
	if err != nil {
		t.Errorf("Failed to compile default patterns: %v", err)
	}
}

func TestConfig_AutoDiscovery(t *testing.T) {
	// Create temporary directory structure
	tempDir, err := ioutil.TempDir("", "gitguardian-autodiscovery-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Save current directory
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	defer os.Chdir(originalDir)

	// Change to temp directory
	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}

	// Create config file in current directory
	configContent := `{
		"verbose": true,
		"max_concurrency": 2
	}`

	err = ioutil.WriteFile(".gitguardian.json", []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Test auto-discovery
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Failed to auto-discover config: %v", err)
	}

	if !cfg.Verbose {
		t.Error("Expected auto-discovered config to have Verbose=true")
	}

	if cfg.MaxConcurrency != 2 {
		t.Errorf("Expected auto-discovered config to have MaxConcurrency=2, got %d", cfg.MaxConcurrency)
	}
}
