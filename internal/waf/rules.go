// Package waf is Aegis: an inline OWASP-CRS-style WAF plus a sliding-window
// per-client rate limiter that wraps Sluice's existing handler chain.
//
// The package is additive and OFF by default. The HTTP middleware (see
// middleware.go) only inspects traffic when the engine is enabled AND a route
// opts in (config.Route.Waf), so an unconfigured gateway is a pure pass-through
// with zero behavior change. Blocked and flagged requests are reported to
// Watchtower through the SAME non-blocking audit emitter the gateway already
// uses, so a slow or down collector can never affect the request path.
package waf

import (
	"net/http"
	"regexp"
	"strings"
)

// Severity labels a rule. They map to additive scores via severityScore so a
// single critical detection blocks at the default threshold while lower-severity
// signals must accumulate.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// severityScore is the points a matching rule contributes to a request's score.
func severityScore(sev string) int {
	switch sev {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	default:
		return 2
	}
}

// Target is a bitmask of the request components a rule inspects.
type Target uint8

const (
	TargetPath      Target = 1 << iota // URL path
	TargetQuery                        // raw + percent-decoded query string
	TargetHeaders                      // all request header values (except Cookie/Authorization)
	TargetUserAgent                    // the User-Agent header value only
	TargetBody                         // request body (up to the inspection cap)
)

// Rule is one compiled detection. Score is derived from Severity at construction
// so callers reason in severities while the engine sums scores.
type Rule struct {
	ID          string
	Severity    string
	Score       int
	Description string
	Targets     Target
	re          *regexp.Regexp
}

// Hit records a single rule firing against a specific request component.
type Hit struct {
	RuleID      string
	Severity    string
	Description string
	Target      string
}

// Detection is the aggregate result of scanning one request: the summed score
// and the individual rule hits that produced it.
type Detection struct {
	Score int
	Hits  []Hit
}

// RuleIDs returns the comma-joined hit rule ids, suitable for an audit detail.
func (d Detection) RuleIDs() string {
	ids := make([]string, 0, len(d.Hits))
	for _, h := range d.Hits {
		ids = append(ids, h.RuleID)
	}
	return strings.Join(ids, ",")
}

// RuleSet is an ordered, immutable collection of compiled rules.
type RuleSet struct {
	rules []Rule
}

// NewRuleSet compiles the given specs into a RuleSet. A spec with an invalid
// pattern is skipped rather than panicking, so a future externally-loaded
// ruleset cannot take the gateway down.
func NewRuleSet(specs []RuleSpec) *RuleSet {
	rs := &RuleSet{}
	for _, s := range specs {
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		rs.rules = append(rs.rules, Rule{
			ID:          s.ID,
			Severity:    s.Severity,
			Score:       severityScore(s.Severity),
			Description: s.Description,
			Targets:     s.Targets,
			re:          re,
		})
	}
	return rs
}

// Len reports the number of compiled rules (used by tests and logging).
func (rs *RuleSet) Len() int { return len(rs.rules) }

// RuleSpec is the uncompiled form of a Rule. The embedded default ruleset and any
// future loader produce these; NewRuleSet compiles Pattern into a regexp.
type RuleSpec struct {
	ID          string
	Severity    string
	Description string
	Targets     Target
	Pattern     string
}

// inputs is the set of request strings a scan runs rules against. It is built
// once per request so each rule does not re-derive request components.
type inputs struct {
	path      string
	query     string
	headers   []string
	userAgent string
	body      string
}

// targetText returns the candidate strings for a given target bit.
func (in inputs) targetText(t Target) []string {
	switch t {
	case TargetPath:
		return []string{in.path}
	case TargetQuery:
		return []string{in.query}
	case TargetHeaders:
		return in.headers
	case TargetUserAgent:
		return []string{in.userAgent}
	case TargetBody:
		return []string{in.body}
	default:
		return nil
	}
}

// targetName renders a target bit for the audit/hit detail.
func targetName(t Target) string {
	switch t {
	case TargetPath:
		return "path"
	case TargetQuery:
		return "query"
	case TargetHeaders:
		return "headers"
	case TargetUserAgent:
		return "user-agent"
	case TargetBody:
		return "body"
	default:
		return "unknown"
	}
}

// allTargets is the fixed iteration order over the single-bit targets.
var allTargets = []Target{TargetPath, TargetQuery, TargetHeaders, TargetUserAgent, TargetBody}

// scan runs every rule against the request inputs and returns the aggregate
// detection. A rule fires at most once per request (the first matching target
// wins) so a value appearing in several components does not multiply the score.
func (rs *RuleSet) scan(in inputs) Detection {
	var det Detection
	for i := range rs.rules {
		r := &rs.rules[i]
		if hit, tgt := ruleMatch(r, in); hit {
			det.Score += r.Score
			det.Hits = append(det.Hits, Hit{
				RuleID:      r.ID,
				Severity:    r.Severity,
				Description: r.Description,
				Target:      targetName(tgt),
			})
		}
	}
	return det
}

// ruleMatch tests a rule against each of its targets, returning the first target
// that matches.
func ruleMatch(r *Rule, in inputs) (bool, Target) {
	for _, t := range allTargets {
		if r.Targets&t == 0 {
			continue
		}
		for _, s := range in.targetText(t) {
			if s != "" && r.re.MatchString(s) {
				return true, t
			}
		}
	}
	return false, 0
}

// headerValues flattens the request headers into scannable strings, skipping the
// credential-bearing headers so the WAF never inspects (or risks logging) secrets.
func headerValues(h http.Header) []string {
	out := make([]string, 0, len(h))
	for name, vals := range h {
		switch http.CanonicalHeaderKey(name) {
		case "Cookie", "Authorization", "Proxy-Authorization":
			continue
		}
		out = append(out, vals...)
	}
	return out
}

// DefaultRuleSpecs is the embedded OWASP-CRS-style baseline. Patterns are
// deliberately conservative (case-insensitive, anchored on unambiguous attack
// markers) to keep false positives low; each critical-severity class blocks on a
// single hit at the default threshold (5). The set covers SQLi, XSS, path
// traversal, RCE/command injection, scanner user-agents, Shellshock, and
// Log4Shell.
var DefaultRuleSpecs = []RuleSpec{
	// SQL injection.
	{
		ID: "SQLI-001", Severity: SeverityCritical, Targets: TargetQuery | TargetBody | TargetPath,
		Description: "SQL injection: UNION SELECT",
		Pattern:     `(?i)union\s+(all\s+)?select\b`,
	},
	{
		ID: "SQLI-002", Severity: SeverityCritical, Targets: TargetQuery | TargetBody | TargetPath,
		Description: "SQL injection: boolean tautology (OR 1=1)",
		Pattern:     `(?i)\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+`,
	},
	{
		ID: "SQLI-003", Severity: SeverityCritical, Targets: TargetQuery | TargetBody,
		Description: "SQL injection: stacked query / comment terminator",
		Pattern:     `(?i)(;\s*(drop|insert|update|delete|alter)\b|'\s*(--|#)|/\*.*\*/)`,
	},
	{
		ID: "SQLI-004", Severity: SeverityHigh, Targets: TargetQuery | TargetBody,
		Description: "SQL injection: time-based probe (SLEEP/BENCHMARK)",
		Pattern:     `(?i)\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(`,
	},

	// Cross-site scripting.
	{
		ID: "XSS-001", Severity: SeverityCritical, Targets: TargetQuery | TargetBody | TargetPath,
		Description: "XSS: <script> tag",
		Pattern:     `(?i)<\s*script\b`,
	},
	{
		ID: "XSS-002", Severity: SeverityCritical, Targets: TargetQuery | TargetBody,
		Description: "XSS: javascript: scheme or inline event handler",
		Pattern:     `(?i)(javascript:|on(error|load|mouseover|click|focus)\s*=)`,
	},
	{
		ID: "XSS-003", Severity: SeverityHigh, Targets: TargetQuery | TargetBody,
		Description: "XSS: dangerous sink (<iframe>/<svg onload>/document.cookie)",
		Pattern:     `(?i)(<\s*(iframe|svg|img)\b[^>]*on\w+\s*=|document\.cookie)`,
	},

	// Path / directory traversal.
	{
		ID: "LFI-001", Severity: SeverityCritical, Targets: TargetPath | TargetQuery,
		Description: "Path traversal: ../ sequence (raw or encoded)",
		Pattern:     `(?i)(\.\.[/\\]|%2e%2e[/\\]|%2e%2e%2f|\.\.%2f)`,
	},
	{
		ID: "LFI-002", Severity: SeverityHigh, Targets: TargetPath | TargetQuery,
		Description: "Path traversal: sensitive file access",
		Pattern:     `(?i)(/etc/passwd|/etc/shadow|boot\.ini|win\.ini|[a-z]:\\windows\\)`,
	},

	// Remote command execution / command injection.
	{
		ID: "RCE-001", Severity: SeverityCritical, Targets: TargetQuery | TargetBody | TargetPath,
		Description: "Command injection: shell metacharacter + command",
		Pattern:     `(?i)(;|\||&&|\$\(|` + "`" + `)\s*(cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python|perl)\b`,
	},
	{
		ID: "RCE-002", Severity: SeverityHigh, Targets: TargetQuery | TargetBody,
		Description: "Command injection: process substitution / backtick exec",
		Pattern:     `(?i)(\$\([^)]+\)|` + "`" + `[^` + "`" + `]+` + "`" + `)`,
	},

	// Known scanners / offensive tooling user-agents.
	{
		ID: "SCAN-001", Severity: SeverityCritical, Targets: TargetUserAgent,
		Description: "Malicious scanner user-agent",
		Pattern:     `(?i)\b(sqlmap|nikto|nmap|masscan|acunetix|nessus|netsparker|dirbuster|gobuster|wpscan|havij|fimap|w3af|zgrab|nuclei|whatweb)\b`,
	},
	{
		ID: "SCAN-002", Severity: SeverityLow, Targets: TargetUserAgent,
		Description: "Generic automation user-agent",
		Pattern:     `(?i)(python-requests|go-http-client|libwww-perl|curl/)`,
	},

	// Shellshock (CVE-2014-6271) — the "() {" function-export marker.
	{
		ID: "SHELL-001", Severity: SeverityCritical, Targets: TargetHeaders | TargetQuery | TargetBody | TargetUserAgent,
		Description: "Shellshock: bash function-export marker",
		Pattern:     `\(\s*\)\s*\{`,
	},

	// Log4Shell (CVE-2021-44228) — the ${jndi:...} lookup marker.
	{
		ID: "LOG4J-001", Severity: SeverityCritical, Targets: TargetHeaders | TargetQuery | TargetBody | TargetPath | TargetUserAgent,
		Description: "Log4Shell: JNDI lookup marker",
		Pattern:     `(?i)\$\{jndi:(ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http)s?:`,
	},
}

// DefaultRuleSet compiles the embedded baseline ruleset.
func DefaultRuleSet() *RuleSet { return NewRuleSet(DefaultRuleSpecs) }
