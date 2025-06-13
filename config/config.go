// config/config.go
package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	IgnoreRules []string `yaml:"ignore_rules"`
	IgnorePaths []string `yaml:"ignore_paths"`
}

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

func (c *Config) MatchesRule(rule string) bool {
	for _, r := range c.IgnoreRules {
		if r == rule {
			return true
		}
	}
	return false
}

func (c *Config) MatchesPath(rel string) bool {
	for _, pat := range c.IgnorePaths {
		if ok, _ := filepath.Match(pat, rel); ok {
			return true
		}
	}
	return false
}
