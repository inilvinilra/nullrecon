package secretscan

import "regexp"

const DetectorsVersion = "nr.rules/v1"

type Detector struct {
	ID         string
	Category   string
	Severity   string
	Pattern    string
	Group      int
	MinEntropy float64
	re         *regexp.Regexp
}

var baseDetectors = []Detector{
	{ID: "aws-access-key", Category: "key", Severity: "high", Pattern: `\b(A(?:KIA|SIA|GPA|IDA|ROA|IPA|NPA|NVA|KID)[0-9A-Z]{16})\b`, Group: 1},
	{ID: "aws-secret-key", Category: "key", Severity: "high", Pattern: `(?i)aws[^0-9a-zA-Z]{0,20}['"]?([0-9a-zA-Z/+]{40})['"]?`, Group: 1, MinEntropy: 4.0},
	{ID: "google-api-key", Category: "key", Severity: "high", Pattern: `\b(AIza[0-9A-Za-z\-_]{35})\b`, Group: 1},
	{ID: "github-token", Category: "token", Severity: "high", Pattern: `\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36})\b`, Group: 1},
	{ID: "github-pat-fine", Category: "token", Severity: "high", Pattern: `\b(github_pat_[0-9A-Za-z_]{22,255})\b`, Group: 1},
	{ID: "slack-token", Category: "token", Severity: "high", Pattern: `\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b`, Group: 1},
	{ID: "stripe-secret", Category: "key", Severity: "critical", Pattern: `\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b`, Group: 1},
	{ID: "google-oauth", Category: "credential", Severity: "medium", Pattern: `\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b`, Group: 1},
	{ID: "private-key", Category: "privatekey", Severity: "critical", Pattern: `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`, Group: 0},
	{ID: "jwt", Category: "token", Severity: "low", Pattern: `\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b`, Group: 1, MinEntropy: 3.5},
	{ID: "slack-webhook", Category: "credential", Severity: "medium", Pattern: `(https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+)`, Group: 1},
	{ID: "npm-token", Category: "token", Severity: "high", Pattern: `\b(npm_[0-9A-Za-z]{36})\b`, Group: 1},
	{ID: "generic-secret-assign", Category: "credential", Severity: "medium", Pattern: `(?i)(?:api[_-]?key|secret|passwd|password|token)['"]?\s*[:=]\s*['"]([0-9a-zA-Z\-_./+=]{16,64})['"]`, Group: 1, MinEntropy: 3.6},
}

type DetectorSet struct {
	detectors []Detector
}

func DefaultDetectors() (*DetectorSet, error) {
	set := &DetectorSet{}
	for _, d := range baseDetectors {
		re, err := regexp.Compile(d.Pattern)
		if err != nil {
			return nil, err
		}
		d.re = re
		set.detectors = append(set.detectors, d)
	}
	return set, nil
}

func (s *DetectorSet) Len() int {
	return len(s.detectors)
}
