package pkg

import "regexp"

// Common secret patterns
var Patterns = map[string]*regexp.Regexp{
	"AWSSecretKey": regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"GithubToken":  regexp.MustCompile(`ghp_[0-9A-Za-z]{36}`),
	// add more as needed...
}
