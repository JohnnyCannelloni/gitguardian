package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/JohnnyCannelloni/gitguardian/internal/config"
)

// defines what to scan for
type ScanType int

const (
	ScanTypeAll ScanType = iota
	ScanTypeSecrets
	ScanTypeDependencies
	ScanTypeSocial
)

// main security scanner
type Scanner struct {
	config *config.Config
}

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

type Results struct {
	ScanTime     time.Time `json:"scan_time"`
	Duration     string    `json:"duration"`
	FilesScanned int       `json:"files_scanned"`
	Issues       []Issue   `json:"issues"`
	Summary      Summary   `json:"summary"`
}

type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// creates a new scanner instance
func New(cfg *config.Config) *Scanner {
	return &Scanner{
		config: cfg,
	}
}

// scans a directory
func (s *Scanner) ScanPath(path string, scanType ScanType) (*Results, error) {
	startTime := time.Now()

	results := &Results{
		ScanTime: startTime,
		Issues:   make([]Issue, 0),
	}

	// collect files to scan
	files, err := s.collectFiles(path)
	if err != nil {
		return nil, fmt.Errorf("failed to collect files: %w", err)
	}

	results.FilesScanned = len(files)

	// scan files concurrently
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

	// close issues channel when all scans complete
	go func() {
		wg.Wait()
		close(issues)
	}()

	for issue := range issues {
		results.Issues = append(results.Issues, issue)
	}

	results.Summary = s.calculateSummary(results.Issues)
	results.Duration = time.Since(startTime).String()

	if s.config.Verbose {
		fmt.Printf("Scanned %d files in %s\n", results.FilesScanned, results.Duration)
	}

	return results, nil
}

// scans a single file
func (s *Scanner) scanFile(filePath string, scanType ScanType) []Issue {
	var issues []Issue

	// check file size
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

	content, err := os.ReadFile(filePath)
	if err != nil {
		return issues
	}

	if isBinary(content) {
		return issues
	}

	contentStr := string(content)

	// scan for secrets
	if scanType == ScanTypeAll || scanType == ScanTypeSecrets {
		issues = append(issues, s.scanSecrets(filePath, contentStr)...)
	}

	// scan dependencies
	if scanType == ScanTypeAll || scanType == ScanTypeDependencies {
		if isDependencyFile(filePath) {
			depIssues, err := s.scanDependencies(filePath, contentStr)
			if err != nil && s.config.Verbose {
				fmt.Printf("Error scanning dependencies in %s: %v\n", filePath, err)
			}
			issues = append(issues, depIssues...)
		}
	}

	if scanType == ScanTypeAll || scanType == ScanTypeSocial {
		if s.config.SocialEngineering.Enabled {
			issues = append(issues, s.scanSocialEngineering(filePath, contentStr)...)
		}
	}

	return issues
}

// scans content for secret patterns
func (s *Scanner) scanSecrets(filePath, content string) []Issue {
	var issues []Issue
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		for _, pattern := range s.config.SecretPatterns {
			matches := pattern.GetCompiledPattern().FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if s.isWhitelisted(match[0]) {
					continue
				}

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

// scans for suspicious commit messages
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

// collects all files to scan
func (s *Scanner) collectFiles(path string) ([]string, error) {
	var files []string

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			dirname := filepath.Base(filePath)
			if shouldSkipDir(dirname) {
				return filepath.SkipDir
			}
			return nil
		}

		// only scan text files
		if shouldScanFile(filePath) {
			files = append(files, filePath)
		}

		return nil
	})

	return files, err
}

// masks a secret for safe display
func (s *Scanner) maskSecret(secret string) string {
	// mask *every* character for secrets up to length 9
	if len(secret) <= 9 {
		return strings.Repeat("*", len(secret))
	}
	// for longer secrets, show 4 chars at each end
	// and mask exactly len(secret)-8 characters in the middle
	return secret[:4] +
		strings.Repeat("*", len(secret)-8) +
		secret[len(secret)-4:]
}

func (s *Scanner) isWhitelisted(value string) bool {
	for _, whitelisted := range s.config.Whitelist {
		if strings.Contains(strings.ToLower(value), strings.ToLower(whitelisted)) {
			return true
		}
	}
	return false
}

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

func isBinary(data []byte) bool {
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

	// check for common config files without extensions
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

func (r *Results) HasIssues() bool {
	return len(r.Issues) > 0
}

// outputs results in JSON format
func (r *Results) OutputJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// outputs results in text format
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
	fmt.Fprintf(w, "  Total: %d\n", r.Summary.Total)

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
