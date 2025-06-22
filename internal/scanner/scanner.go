package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yourusername/gitguardian/internal/config"
)

// ScanType defines what to scan for
type ScanType int

const (
	ScanTypeAll ScanType = iota
	ScanTypeSecrets
	ScanTypeDependencies
	ScanTypeSocial
)

// Scanner is the main security scanner
type Scanner struct {
	config *config.Config
}

// Issue represents a security issue found during scanning
type Issue struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	File        string    `json:"file"`
	Line        int       `json:"line"`
	Column      int       `json:"column"`
	Description string    `json:"description"`
	Content     string    `json:"content"`
	Rule        string    `json:"rule"`
	Timestamp   time.Time `json:"timestamp"`
}

// Results holds all scan results
type Results struct {
	ScanTime     time.Time `json:"scan_time"`
	Duration     string    `json:"duration"`
	FilesScanned int       `json:"files_scanned"`
	Issues       []Issue   `json:"issues"`
	Summary      Summary   `json:"summary"`
}

// Summary provides a summary of the scan results
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// New creates a new scanner instance
func New(cfg *config.Config) *Scanner {
	return &Scanner{
		config: cfg,
	}
}

// ScanPath scans a directory or file for security issues
func (s *Scanner) ScanPath(path string, scanType ScanType) (*Results, error) {
	startTime := time.Now()

	results := &Results{
		ScanTime: startTime,
		Issues:   make([]Issue, 0),
	}

	// Collect files to scan
	files, err := s.collectFiles(path)
	if err != nil {
		return nil, fmt.Errorf("failed to collect files: %w", err)
	}

	results.FilesScanned = len(files)

	// Scan files concurrently
	issues := make(chan Issue, 100)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.config.MaxConcurrency)

	for _, file := range files {
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fileIssues := s.scanFile(f, scanType)
			for _, issue := range fileIssues {
				issues <- issue
			}
		}(file)
	}

	// Close issues channel when all scans complete
	go func() {
		wg.Wait()
		close(issues)
	}()

	// Collect all issues
	for issue := range issues {
		results.Issues = append(results.Issues, issue)
	}

	// Calculate summary
	results.Summary = s.calculateSummary(results.Issues)
	results.Duration = time.Since(startTime).String()

	if s.config.Verbose {
		fmt.Printf("Scanned %d files in %s\n", results.FilesScanned, results.Duration)
	}

	return results, nil
}

// scanFile scans a single file for security issues
func (s *Scanner) scanFile(filePath string, scanType ScanType) []Issue {
	var issues []Issue

	// Check file size
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return issues
	}

	if fileInfo.Size() > s.config.MaxFileSize {
		if s.config.Verbose {
			fmt.Printf("Skipping large file: %s (%d bytes)\n", filePath, fileInfo.Size())
		}
		return issues
	}

	// Read file content
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return issues
	}

	// Skip binary files
	if isBinary(content) {
		return issues
	}

	contentStr := string(content)

	// Scan for secrets
	if scanType == ScanTypeAll || scanType == ScanTypeSecrets {
		issues = append(issues, s.scanSecrets(filePath, contentStr)...)
	}

	// Scan dependencies
	if scanType == ScanTypeAll || scanType == ScanTypeDependencies {
		if isDependencyFile(filePath) {
			depIssues, err := s.scanDependencies(filePath, contentStr)
			if err != nil && s.config.Verbose {
				fmt.Printf("Error scanning dependencies in %s: %v\n", filePath, err)
			}
			issues = append(issues, depIssues...)
		}
	}

	// Social engineering detection
	if scanType == ScanTypeAll || scanType == ScanTypeSocial {
		if s.config.SocialEngineering.Enabled {
			issues = append(issues, s.scanSocialEngineering(filePath, contentStr)...)
		}
	}

	return issues
}

// scanSecrets scans content for secret patterns
func (s *Scanner) scanSecrets(filePath, content string) []Issue {
	var issues []Issue
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		for _, pattern := range s.config.SecretPatterns {
			matches := pattern.GetCompiledPattern().FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				// Check whitelist
				if s.isWhitelisted(match[0]) {
					continue
				}

				// Extract the actual secret if there's a capture group
				secret := match[0]
				if len(match) > 1 {
					secret = match[1]
				}

				issues = append(issues, Issue{
					Type:        "secret",
					Severity:    pattern.Severity,
					File:        filePath,
					Line:        lineNum + 1,
					Column:      strings.Index(line, match[0]) + 1,
					Description: pattern.Description,
					Content:     s.maskSecret(secret),
					Rule:        pattern.Name,
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return issues
}

// scanSocialEngineering scans for suspicious commit messages or comments
func (s *Scanner) scanSocialEngineering(filePath, content string) []Issue {
	var issues []Issue
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		lowerLine := strings.ToLower(line)

		for _, keyword := range s.config.SocialEngineering.SuspiciousKeywords {
			if strings.Contains(lowerLine, strings.ToLower(keyword)) {
				issues = append(issues, Issue{
					Type:        "social",
					Severity:    "medium",
					File:        filePath,
					Line:        lineNum + 1,
					Column:      strings.Index(lowerLine, strings.ToLower(keyword)) + 1,
					Description: fmt.Sprintf("Suspicious keyword detected: %s", keyword),
					Content:     line,
					Rule:        "Social Engineering Detection",
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return issues
}

// collectFiles recursively collects all files to scan
func (s *Scanner) collectFiles(path string) ([]string, error) {
	var files []string

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			// Skip common directories we don't want to scan
			dirname := filepath.Base(filePath)
			if shouldSkipDir(dirname) {
				return filepath.SkipDir
			}
			return nil
		}

		// Only scan text files
		if shouldScanFile(filePath) {
			files = append(files, filePath)
		}

		return nil
	})

	return files, err
}

// maskSecret masks a secret for safe display
func (s *Scanner) maskSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:4] + strings.Repeat("*", len(secret)-8) + secret[len(secret)-4:]
}

// isWhitelisted checks if a value is in the whitelist
func (s *Scanner) isWhitelisted(value string) bool {
	for _, whitelisted := range s.config.Whitelist {
		if strings.Contains(strings.ToLower(value), strings.ToLower(whitelisted)) {
			return true
		}
	}
	return false
}

// calculateSummary calculates summary statistics
func (s *Scanner) calculateSummary(issues []Issue) Summary {
	summary := Summary{}

	for _, issue := range issues {
		switch issue.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
		summary.Total++
	}

	return summary
}

// Helper functions

func isBinary(data []byte) bool {
	// Simple binary detection - check for null bytes in first 512 bytes
	limit := len(data)
	if limit > 512 {
		limit = 512
	}

	for i := 0; i < limit; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func shouldSkipDir(dirname string) bool {
	skipDirs := []string{
		".git", ".svn", ".hg",
		"node_modules", "vendor", ".venv", "venv",
		"target", "build", "dist", "out",
		".idea", ".vscode",
	}

	for _, skip := range skipDirs {
		if dirname == skip {
			return true
		}
	}
	return false
}

func shouldScanFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Text file extensions
	textExts := []string{
		".go", ".py", ".js", ".ts", ".java", ".cpp", ".c", ".cs", ".php",
		".rb", ".sh", ".bash", ".zsh", ".fish",
		".yaml", ".yml", ".json", ".xml", ".toml", ".ini", ".cfg", ".conf",
		".txt", ".md", ".rst", ".html", ".css", ".scss", ".sass",
		".sql", ".env", ".envrc", ".dockerignore", ".gitignore",
		".Dockerfile", "",
	}

	for _, textExt := range textExts {
		if ext == textExt {
			return true
		}
	}

	// Check for common config files without extensions
	basename := filepath.Base(filePath)
	configFiles := []string{
		"Dockerfile", "Makefile", "Jenkinsfile", "Vagrantfile",
		"docker-compose.yml", "docker-compose.yaml",
	}

	for _, configFile := range configFiles {
		if basename == configFile {
			return true
		}
	}

	return false
}

func isDependencyFile(filePath string) bool {
	basename := strings.ToLower(filepath.Base(filePath))
	depFiles := []string{
		"package.json", "package-lock.json", "yarn.lock",
		"go.mod", "go.sum",
		"requirements.txt", "pipfile", "pipfile.lock", "poetry.lock",
		"gemfile", "gemfile.lock",
		"composer.json", "composer.lock",
		"pom.xml", "build.gradle", "gradle.lockfile",
		"cargo.toml", "cargo.lock",
	}

	for _, depFile := range depFiles {
		if basename == depFile {
			return true
		}
	}
	return false
}

// HasIssues returns true if there are any issues found
func (r *Results) HasIssues() bool {
	return len(r.Issues) > 0
}

// OutputJSON outputs results in JSON format
func (r *Results) OutputJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// OutputText outputs results in human-readable text format
func (r *Results) OutputText(w io.Writer) error {
	fmt.Fprintf(w, "GitGuardian Security Scan Results\n")
	fmt.Fprintf(w, "=================================\n\n")
	fmt.Fprintf(w, "Scan completed at: %s\n", r.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Duration: %s\n", r.Duration)
	fmt.Fprintf(w, "Files scanned: %d\n\n", r.FilesScanned)

	if len(r.Issues) == 0 {
		fmt.Fprintf(w, "✅ No security issues found!\n")
		return nil
	}

	fmt.Fprintf(w, "Summary:\n")
	fmt.Fprintf(w, "  Critical: %d\n", r.Summary.Critical)
	fmt.Fprintf(w, "  High:     %d\n", r.Summary.High)
	fmt.Fprintf(w, "  Medium:   %d\n", r.Summary.Medium)
	fmt.Fprintf(w, "  Low:      %d\n", r.Summary.Low)
	fmt.Fprintf(w, "  Total:    %d\n\n", r.Summary.Total)

	fmt.Fprintf(w, "Issues Found:\n")
	fmt.Fprintf(w, "=============\n\n")

	for i, issue := range r.Issues {
		severityIcon := getSeverityIcon(issue.Severity)
		fmt.Fprintf(w, "%d. %s [%s] %s\n", i+1, severityIcon, strings.ToUpper(issue.Severity), issue.Description)
		fmt.Fprintf(w, "   File: %s:%d:%d\n", issue.File, issue.Line, issue.Column)
		fmt.Fprintf(w, "   Rule: %s\n", issue.Rule)
		if issue.Content != "" {
			fmt.Fprintf(w, "   Content: %s\n", issue.Content)
		}
		fmt.Fprintf(w, "\n")
	}

	return nil
}

func getSeverityIcon(severity string) string {
	switch severity {
	case "critical":
		return "🚨"
	case "high":
		return "⚠️"
	case "medium":
		return "⚡"
	case "low":
		return "ℹ️"
	default:
		return "❓"
	}
}
