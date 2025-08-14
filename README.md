GitGuardian 🛡️
A comprehensive security scanner for Git repositories that prevents sensitive information leaks and detects vulnerabilities in dependencies. Built in Go for speed and reliability.

🚀 Features
🔐 Secret Detection
API Keys: AWS, GitHub, Slack, and more
Passwords: Generic password patterns
Tokens: JWT, OAuth tokens, personal access tokens
Private Keys: RSA, SSH private keys
Custom Patterns: Configurable regex patterns
🔍 Dependency Scanning
Vulnerability Detection: Integration with OSV (Open Source Vulnerabilities) database
Multi-Language Support: Node.js, Go, Python, Ruby, PHP, Java, Rust
Real-time Updates: Latest vulnerability data from security databases
🎯 Social Engineering Detection
Suspicious Keywords: Detects potentially malicious commit messages
Pattern Recognition: Identifies common social engineering tactics
Configurable Rules: Customize detection patterns
⚡ Git Integration
Pre-commit Hooks: Scan staged files before commits
Pre-push Hooks: Validate changes before pushing
Commit Message Scanning: Check commit messages for suspicious content
CI/CD Integration: GitHub Actions, GitLab CI, and more
📦 Installation
From Source
bash
# Clone the repository
git clone https://github.com/yourusername/gitguardian.git
cd gitguardian

# Build and install
make install

# Or install to system PATH (requires sudo)
make install-system

🏃‍♂️ Quick Start
1. Scan Your Repository
bash
# Scan current directory
gitguardian -path .

# Scan specific directory
gitguardian -path /path/to/repo

# Scan only for secrets
gitguardian -path . -secrets-only

# Scan only dependencies
gitguardian -path . -deps-only
2. Install Git Hooks
bash
# Install hooks in current repository
gitguardian -install-hooks

# This installs:
# - pre-commit: Scans staged files
# - pre-push: Scans changed files before push
# - commit-msg: Checks commit messages

⚙️ Configuration
GitGuardian looks for configuration in these locations (in order):

.gitguardian.json (current directory)
gitguardian.json (current directory)
~/.gitguardian.json (home directory)
Generate Default Configuration
bash
make config
# Or manually create .gitguardian.json
Configuration Example
json
{
  "verbose": false,
  "max_file_size": 10485760,
  "max_concurrency": 4,
  "secret_patterns": [
    {
      "name": "AWS Access Key",
      "pattern": "AKIA[0-9A-Z]{16}",
      "description": "Amazon Web Services Access Key",
      "severity": "critical"
    }
  ],
  "whitelist": [
    "example.com",
    "localhost",
    "test",
    "demo"
  ],
  "dependency_apis": {
    "osv_enabled": true,
    "cache_enabled": true,
    "cache_duration": 24
  },
  "social_engineering": {
    "enabled": true,
    "suspicious_keywords": [
      "hack",
      "backdoor",
      "bypass",
      "disable security"
    ]
  }
}

# Bypass hooks when needed (NOT RECOMMENDED)
git commit --no-verify
git push --no-verify

# Run tests
make test

# Run with coverage
make test-coverage



make test

# With coverage
make test-coverage

# Benchmarks
make benchmark

# Security check
make security-check
Test Your Configuration
bash
# Create test files with known patterns
echo 'AKIAIOSFODNN7EXAMPLE' > test_secret.txt

# Run scanner
gitguardian -path . -verbose

# Should detect the AWS key pattern
📋 Command Line Options
Usage: gitguardian [OPTIONS]

Options:
  -path string
        Path to scan (default ".")
  -install-hooks
        Install Git hooks
  -config string
        Configuration file path
  -verbose
        Verbose output
  -secrets-only
        Only scan for secrets
  -deps-only
        Only scan dependencies
  -format string
        Output format (text, json) (default "text")
  -help
        Show help message
🔒 Security Considerations
False Positives
GitGuardian may occasionally flag legitimate strings as secrets. To handle this:

Use Whitelisting: Add known safe patterns to the whitelist in configuration
Adjust Patterns: Modify regex patterns to be more specific
Context Checking: The tool considers context like file types and comments
Performance
File Size Limits: Large files are skipped by default (configurable)
Concurrency: Parallel scanning for better performance
Selective Scanning: Hook mode only scans changed files
Privacy
Local Scanning: All secret detection happens locally
API Calls: Only dependency scanning makes external API calls to vulnerability databases
No Data Transmission: Your code never leaves your environment during secret scanning




