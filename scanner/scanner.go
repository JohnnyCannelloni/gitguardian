package scanner

// Finding represents a single secret or issue found
type Finding struct {
	File    string
	Line    int
	Content string
	Rule    string
}

// ScanPath walks a directory or file and returns Findings
func ScanPath(path string) ([]Finding, error) {
	// TODO: walk filesystem, call ScanFile
	return nil, nil
}

// ScanFile reads a single file and applies regex checks
func ScanFile(path string) ([]Finding, error) {
	// TODO: read file, apply patterns from pkg/patterns
	return nil, nil
}
