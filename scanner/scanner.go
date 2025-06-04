// scanner/scanner.go
package scanner

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/JohnnyCannelloni/gitguardian/config"
	"github.com/JohnnyCannelloni/gitguardian/pkg"
	ignore "github.com/sabhiram/go-gitignore" // for .gitignore parsing
)

// Finding represents a detected secret (or issue) in a file.
type Finding struct {
	File    string // Path to the file
	Line    int    // 1-based line number
	Content string // The full line text that matched
	Rule    string // The name of the matching regex (key from pkg.Patterns)
}

// ScanFile opens and scans a single file, line-by-line, looking for any regex matches.
// It skips obvious binaries (ELF or PE headers).
func ScanFile(path string) ([]Finding, error) {
	// 1) Quick check: read first few bytes to detect ELF/PE signatures
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 4 && (bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) ||
		bytes.HasPrefix(data, []byte{'M', 'Z'})) {
		// Looks like a binary → skip
		return nil, nil
	}

	// 2) Re-open file for line-by-line scanning
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	scanner := bufio.NewScanner(f)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		for ruleName, re := range pkg.Patterns {
			if loc := re.FindStringIndex(line); loc != nil {
				findings = append(findings, Finding{
					File:    path,
					Line:    lineNo,
					Content: line,
					Rule:    ruleName,
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return findings, err
	}
	return findings, nil
}

// ScanPath walks the root directory or single file, respects .gitignore patterns,
// and scans all regular files in parallel via a worker pool.
// Then it filters out any results that match cfg.IgnoreRules or cfg.IgnorePaths.
func ScanPath(root string, cfg *config.Config) ([]Finding, error) {
	// 1) Attempt to load .gitignore from the root
	var ign *ignore.GitIgnore
	if fi, err := os.Stat(filepath.Join(root, ".gitignore")); err == nil && !fi.IsDir() {
		ign, _ = ignore.CompileIgnoreFile(filepath.Join(root, ".gitignore"))
	}

	// 2) Collect all non-ignored, non-directory paths
	var allPaths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip .git directory itself
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}

		// Apply .gitignore rules if present (skip files or directories that match)
		if ign != nil && ign.MatchesPath(path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// If it’s a file (not a directory), add it to the list
		if !d.IsDir() {
			allPaths = append(allPaths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// 3) Set up a worker pool to scan files concurrently
	numWorkers := runtime.NumCPU() / 2
	if numWorkers < 1 {
		numWorkers = 1
	}

	jobs := make(chan string, len(allPaths))
	results := make(chan []Finding, len(allPaths))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				// Skip large files > 5 MB and known binary extensions
				ext := filepath.Ext(path)
				skipExt := map[string]bool{
					".exe":    true,
					".png":    true,
					".jpg":    true,
					".gif":    true,
					".jar":    true,
					".min.js": true,
				}
				if skipExt[ext] {
					continue
				}
				if fi, _ := os.Stat(path); fi.Size() > 5*1024*1024 {
					continue
				}

				finds, err := ScanFile(path)
				if err == nil && len(finds) > 0 {
					results <- finds
				}
			}
		}()
	}

	// Enqueue all paths
	for _, p := range allPaths {
		jobs <- p
	}
	close(jobs)

	// Once workers finish, close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// 4) Collect and filter findings
	var allFindings []Finding
	for batch := range results {
		allFindings = append(allFindings, batch...)
	}

	var filtered []Finding
	for _, f := range allFindings {
		// If rule is in ignore_rules, skip
		if cfg.MatchesRule(f.Rule) {
			continue
		}
		// If file path matches any ignore_paths glob, skip
		relPath, err := filepath.Rel(root, f.File)
		if err == nil && cfg.MatchesPath(relPath) {
			continue
		}
		filtered = append(filtered, f)
	}

	return filtered, nil
}
