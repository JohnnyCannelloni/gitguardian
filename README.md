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
Using Go Install
bash
go install github.com/yourusername/gitguardian@latest
Download Pre-built Binaries
Download the latest release from GitHub Releases.

Using Homebrew (Coming Soon)
bash
brew install gitguardian
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
3. Configure CI/CD
Copy the provided GitHub Actions workflow:

bash
mkdir -p .github/workflows
cp .github/workflows/gitguardian.yml .github/workflows/
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
🔧 Usage Examples
Basic Scanning
bash
# Scan with verbose output
gitguardian -path . -verbose

# Output in JSON format
gitguardian -path . -format json

# Scan specific file types only
gitguardian -path . -secrets-only -verbose
Git Hook Usage
After installing hooks with -install-hooks:

bash
# Hooks run automatically
git add .
git commit -m "Add new feature"  # pre-commit hook runs

git push origin main  # pre-push hook runs

# Bypass hooks when needed (NOT RECOMMENDED)
git commit --no-verify
git push --no-verify
CI/CD Integration
The tool integrates seamlessly with CI/CD pipelines:

yaml
# Example GitHub Actions step
- name: Security Scan
  run: |
    gitguardian -path . -format json > results.json
    if [ $(jq '.summary.total' results.json) -gt 0 ]; then
      echo "Security issues found!"
      exit 1
    fi
📊 Output Formats
Text Output (Default)
GitGuardian Security Scan Results
=================================

Scan completed at: 2025-01-20 15:30:45
Duration: 2.3s
Files scanned: 156

Summary:
  Critical: 1
  High:     2
  Medium:   3
  Low:      1
  Total:    7

Issues Found:
=============

1. 🚨 [CRITICAL] Amazon Web Services Access Key
   File: config/aws.js:15:8
   Rule: AWS Access Key
   Content: AKIA****EXAMPLE

2. ⚠️ [HIGH] GitHub Personal Access Token
   File: scripts/deploy.sh:23:15
   Rule: GitHub Token
   Content: ghp_****example
JSON Output
json
{
  "scan_time": "2025-01-20T15:30:45Z",
  "duration": "2.3s",
  "files_scanned": 156,
  "issues": [
    {
      "type": "secret",
      "severity": "critical",
      "file": "config/aws.js",
      "line": 15,
      "column": 8,
      "description": "Amazon Web Services Access Key",
      "content": "AKIA****EXAMPLE",
      "rule": "AWS Access Key",
      "timestamp": "2025-01-20T15:30:45Z"
    }
  ],
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 1,
    "total": 7
  }
}
🛠️ Development
Prerequisites
Go 1.21 or later
Git
Setup Development Environment
bash
# Clone repository
git clone https://github.com/yourusername/gitguardian.git
cd gitguardian

# Setup development tools
make dev-setup

# Build
make build

# Run tests
make test

# Run with coverage
make test-coverage

# Format code
make fmt

# Lint
make lint
Project Structure
gitguardian/
├── cmd/
│   └── gitguardian/          # CLI entry point
├── internal/
│   ├── config/              # Configuration management
│   ├── scanner/             # Core scanning logic
│   └── hooks/               # Git hooks integration
├── .github/
│   └── workflows/           # CI/CD workflows
├── docs/                    # Documentation
├── examples/                # Example configurations
├── Makefile                 # Build automation
├── go.mod                   # Go module definition
└── README.md               # This file
Adding New Secret Patterns
Edit your configuration file or modify internal/config/config.go
Add new SecretPattern entries:
go
{
    Name:        "Custom API Key",
    Pattern:     `api[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\']?`,
    Description: "Custom API Key Pattern",
    Severity:    "high",
}
Test your pattern with real and test data
Contributing
Fork the repository
Create a feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request
🧪 Testing
Run Tests
bash
# All tests
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
🤝 Support
Issues and Bugs
Report issues on GitHub Issues.

Feature Requests
We welcome feature requests! Please:

Check existing issues first
Provide clear use cases
Consider contributing the feature yourself
Security Issues
For security vulnerabilities, please email security@yourcompany.com instead of opening public issues.

📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments
OSV Database for vulnerability data
Go for the excellent standard library
The security community for vulnerability research and disclosure
🗺️ Roadmap
Version 1.1
 Web dashboard for scan results
 Integration with more vulnerability databases
 Support for more languages and package managers
 Advanced ML-based secret detection
Version 1.2
 Team collaboration features
 Custom rule sharing
 Advanced reporting and analytics
 Plugin system for extensibility
Built with ❤️ by [Your Name] as part of Computer Science BSc project.

