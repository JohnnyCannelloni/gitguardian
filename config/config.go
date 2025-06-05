// config/config.go
package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the contents of .gitguardian.yml
type Config struct {
	IgnoreRules []string `yaml:"ignore_rules"`
	IgnorePaths []string `yaml:"ignore_paths"`
}

// LoadConfig attempts to read a .gitguardian.yml in the given root.
// If the file does not exist, it returns an empty Config (no ignores).
func LoadConfig(root string) (*Config, error) {
	cfgPath := filepath.Join(root, ".gitguardian.yml")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		return &Config{}, nil
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// MatchesRule returns true if the given rule is in IgnoreRules.
func (c *Config) MatchesRule(rule string) bool {
	for _, r := range c.IgnoreRules {
		if r == rule {
			return true
		}
	}
	return false
}

// MatchesPath returns true if the given relative path matches any IgnorePaths glob.
func (c *Config) MatchesPath(relPath string) bool {
	for _, pattern := range c.IgnorePaths {
		ok, _ := filepath.Match(pattern, relPath)
		if ok {
			return true
		}
	}
	return false
}
