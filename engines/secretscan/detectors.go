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
	{ID: "aws-mws-token", Category: "token", Severity: "high", Pattern: `\b(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`, Group: 1},
	{ID: "google-api-key", Category: "key", Severity: "high", Pattern: `\b(AIza[0-9A-Za-z\-_]{35})\b`, Group: 1},
	{ID: "google-oauth", Category: "credential", Severity: "medium", Pattern: `\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b`, Group: 1},
	{ID: "gcp-service-account", Category: "credential", Severity: "critical", Pattern: `"type":\s*"service_account"`, Group: 0},
	{ID: "firebase-cloud-messaging", Category: "key", Severity: "high", Pattern: `\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})\b`, Group: 1},
	{ID: "azure-storage-key", Category: "credential", Severity: "critical", Pattern: `AccountKey=([A-Za-z0-9+/]{86}==)`, Group: 1},
	{ID: "github-token", Category: "token", Severity: "high", Pattern: `\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36})\b`, Group: 1},
	{ID: "github-pat-fine", Category: "token", Severity: "high", Pattern: `\b(github_pat_[0-9A-Za-z_]{22,255})\b`, Group: 1},
	{ID: "gitlab-pat", Category: "token", Severity: "high", Pattern: `\b(glpat-[0-9A-Za-z_-]{20})\b`, Group: 1},
	{ID: "gitlab-runner-token", Category: "token", Severity: "high", Pattern: `\b(GR1348941[0-9A-Za-z_-]{20})\b`, Group: 1},
	{ID: "gitlab-pipeline-trigger", Category: "token", Severity: "high", Pattern: `\b(glptt-[0-9a-f]{40})\b`, Group: 1},
	{ID: "slack-token", Category: "token", Severity: "high", Pattern: `\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b`, Group: 1},
	{ID: "slack-app-token", Category: "token", Severity: "high", Pattern: `\b(xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]+)\b`, Group: 1},
	{ID: "slack-webhook", Category: "credential", Severity: "medium", Pattern: `(https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+)`, Group: 1},
	{ID: "discord-bot-token", Category: "token", Severity: "high", Pattern: `\b([MNO][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})\b`, Group: 1, MinEntropy: 3.5},
	{ID: "discord-webhook", Category: "credential", Severity: "medium", Pattern: `(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,80})`, Group: 1},
	{ID: "telegram-bot-token", Category: "token", Severity: "high", Pattern: `\b([0-9]{8,10}:[A-Za-z0-9_-]{35})\b`, Group: 1},
	{ID: "stripe-secret", Category: "key", Severity: "critical", Pattern: `\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b`, Group: 1},
	{ID: "square-access-token", Category: "token", Severity: "high", Pattern: `\b(sq0atp-[0-9A-Za-z_-]{22})\b`, Group: 1},
	{ID: "square-oauth-secret", Category: "credential", Severity: "high", Pattern: `\b(sq0csp-[0-9A-Za-z_-]{43})\b`, Group: 1},
	{ID: "paypal-braintree", Category: "token", Severity: "high", Pattern: `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`, Group: 0},
	{ID: "twilio-api-key", Category: "key", Severity: "high", Pattern: `\b(SK[0-9a-fA-F]{32})\b`, Group: 1},
	{ID: "twilio-account-sid", Category: "credential", Severity: "medium", Pattern: `\b(AC[0-9a-fA-F]{32})\b`, Group: 1},
	{ID: "sendgrid-api-key", Category: "key", Severity: "high", Pattern: `\b(SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43})\b`, Group: 1},
	{ID: "mailgun-api-key", Category: "key", Severity: "high", Pattern: `\b(key-[0-9a-zA-Z]{32})\b`, Group: 1, MinEntropy: 3.5},
	{ID: "mailchimp-api-key", Category: "key", Severity: "high", Pattern: `\b([0-9a-f]{32}-us[0-9]{1,2})\b`, Group: 1},
	{ID: "postman-api-key", Category: "key", Severity: "high", Pattern: `\b(PMAK-[0-9a-f]{24}-[0-9a-f]{34})\b`, Group: 1},
	{ID: "npm-token", Category: "token", Severity: "high", Pattern: `\b(npm_[0-9A-Za-z]{36})\b`, Group: 1},
	{ID: "pypi-upload-token", Category: "token", Severity: "high", Pattern: `\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b`, Group: 1},
	{ID: "rubygems-token", Category: "token", Severity: "high", Pattern: `\b(rubygems_[0-9a-f]{48})\b`, Group: 1},
	{ID: "shopify-token", Category: "token", Severity: "high", Pattern: `\b((?:shpat|shpca|shppa|shpss)_[0-9a-fA-F]{32})\b`, Group: 1},
	{ID: "openai-api-key", Category: "key", Severity: "high", Pattern: `\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b`, Group: 1},
	{ID: "anthropic-api-key", Category: "key", Severity: "high", Pattern: `\b(sk-ant-[A-Za-z0-9-]{20,})\b`, Group: 1},
	{ID: "huggingface-token", Category: "token", Severity: "high", Pattern: `\b(hf_[A-Za-z0-9]{34})\b`, Group: 1},
	{ID: "digitalocean-token", Category: "token", Severity: "high", Pattern: `\b(do[opr]_v1_[a-f0-9]{64})\b`, Group: 1},
	{ID: "databricks-token", Category: "token", Severity: "high", Pattern: `\b(dapi[0-9a-f]{32})\b`, Group: 1},
	{ID: "new-relic-key", Category: "key", Severity: "high", Pattern: `\b(NRAK-[A-Z0-9]{27})\b`, Group: 1},
	{ID: "sentry-dsn", Category: "credential", Severity: "medium", Pattern: `(https://[0-9a-f]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+)`, Group: 1},
	{ID: "age-secret-key", Category: "privatekey", Severity: "critical", Pattern: `\b(AGE-SECRET-KEY-1[0-9A-Z]{58})\b`, Group: 1},
	{ID: "facebook-access-token", Category: "token", Severity: "high", Pattern: `\b(EAACEdEose0cBA[0-9A-Za-z]{20,})\b`, Group: 1},
	{ID: "private-key", Category: "privatekey", Severity: "critical", Pattern: `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`, Group: 0},
	{ID: "jwt", Category: "token", Severity: "low", Pattern: `\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b`, Group: 1, MinEntropy: 3.5},
	{ID: "basic-auth-url", Category: "credential", Severity: "high", Pattern: `\b([a-zA-Z][a-zA-Z0-9+.-]*://[^:@/\s]+:[^@/\s]{3,}@[^/\s]+)`, Group: 1, MinEntropy: 2.6},
	{ID: "connection-string-password", Category: "credential", Severity: "high", Pattern: `(?i)(?:password|pwd)\s*=\s*([^;'"\s]{6,})`, Group: 1, MinEntropy: 2.8},
	{ID: "linear-api-key", Category: "token", Severity: "high", Pattern: `\b(lin_api_[0-9A-Za-z]{40})\b`, Group: 1},
	{ID: "planetscale-token", Category: "token", Severity: "high", Pattern: `\b(pscale_tkn_[0-9A-Za-z._\-]{32,64})\b`, Group: 1},
	{ID: "planetscale-password", Category: "credential", Severity: "high", Pattern: `\b(pscale_pw_[0-9A-Za-z._\-]{32,64})\b`, Group: 1},
	{ID: "doppler-token", Category: "token", Severity: "high", Pattern: `\b(dp\.(?:pt|st|ct|sa|scim|audit)\.[0-9A-Za-z]{40,44})\b`, Group: 1},
	{ID: "grafana-service-account", Category: "token", Severity: "high", Pattern: `\b(glsa_[0-9A-Za-z]{32}_[0-9A-Fa-f]{8})\b`, Group: 1},
	{ID: "dockerhub-pat", Category: "token", Severity: "high", Pattern: `\b(dckr_pat_[0-9A-Za-z_\-]{27,})`, Group: 1, MinEntropy: 3.5},
	{ID: "atlassian-api-token", Category: "token", Severity: "high", Pattern: `\b(ATATT3[0-9A-Za-z_=\-]{100,})`, Group: 1, MinEntropy: 4.0},
	{ID: "dropbox-token", Category: "token", Severity: "high", Pattern: `\b(sl\.[A-Za-z0-9_\-]{130,152})\b`, Group: 1, MinEntropy: 4.0},
	{ID: "figma-token", Category: "token", Severity: "high", Pattern: `\b(figd_[0-9A-Za-z_\-]{40,})`, Group: 1, MinEntropy: 3.5},
	{ID: "clickup-token", Category: "token", Severity: "medium", Pattern: `\b(pk_[0-9]{6,8}_[0-9A-Z]{32})\b`, Group: 1},
	{ID: "stripe-restricted-key", Category: "key", Severity: "high", Pattern: `\b(rk_live_[0-9A-Za-z]{24,})`, Group: 1, MinEntropy: 3.5},
	{ID: "razorpay-key", Category: "key", Severity: "high", Pattern: `\b(rzp_(?:live|test)_[0-9A-Za-z]{14})\b`, Group: 1},
	{ID: "hashicorp-vault-token", Category: "token", Severity: "critical", Pattern: `\b(hvs\.[A-Za-z0-9_\-]{90,120})`, Group: 1, MinEntropy: 4.0},
	{ID: "terraform-cloud-token", Category: "token", Severity: "high", Pattern: `\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{60,70})\b`, Group: 1},
	{ID: "prefect-api-key", Category: "token", Severity: "medium", Pattern: `\b(pnu_[0-9a-zA-Z]{36})\b`, Group: 1},
	{ID: "openai-project-key", Category: "key", Severity: "high", Pattern: `\b(sk-proj-[0-9A-Za-z_\-]{40,})`, Group: 1, MinEntropy: 3.8},
	{ID: "generic-secret-assign", Category: "credential", Severity: "medium", Pattern: `(?i)(?:api[_-]?key|secret|passwd|password|token|auth[_-]?token|access[_-]?token|client[_-]?secret)['"]?\s*[:=]\s*['"]([0-9a-zA-Z\-_./+=]{16,64})['"]`, Group: 1, MinEntropy: 3.6},
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
