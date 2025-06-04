// pkg/patterns.go
package pkg

import "regexp"

// Patterns maps a rule name to its compiled regex.
//
// Whenever a line matches one of these regexes, we emit a Finding with that rule name.
var Patterns = map[string]*regexp.Regexp{
	// ─── Cloud Credentials ─────────────────────────────────────────────────────
	"AWSAccessKeyID":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`), // AWS Access Key ID
	"AWSSecretAccessKey": regexp.MustCompile(`(?i)aws(.{0,20})?(secret|sa)[:=]\s*([A-Za-z0-9/+=]{40})`),
	"GCPServiceAccount":  regexp.MustCompile(`"type":\s*"service_account"`), // GCP JSON key pattern

	// ─── VCS Tokens ───────────────────────────────────────────────────────────
	"GitHubToken": regexp.MustCompile(`ghp_[0-9A-Za-z]{36}`),      // GitHub PAT
	"GitLabToken": regexp.MustCompile(`glpat-[0-9A-Za-z\-]{20,}`), // GitLab PAT

	// ─── Database URIs ─────────────────────────────────────────────────────────
	"MongoDBURI": regexp.MustCompile(`mongodb(\+srv)?:\/\/[^\s]+`),
	"SQLDSN":     regexp.MustCompile(`(?i)(mysql|postgres|mongodb)\://[^\s]+`),

	// ─── Generic High-Entropy Strings ──────────────────────────────────────────
	"HighEntropy": regexp.MustCompile(`[A-Za-z0-9/+=]{40,}`), // base64-like long

	// ─── Private Key Blocks ────────────────────────────────────────────────────
	"PrivateKey": regexp.MustCompile(`-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----`),
}
