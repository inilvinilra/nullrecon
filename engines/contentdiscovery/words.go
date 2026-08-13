package contentdiscovery

var defaultWords = []string{
	"admin", "administrator", "login", "logout", "dashboard", "portal",
	"api", "api/v1", "api/v2", "graphql", "swagger", "openapi.json",
	"config", "config.json", "configuration", "settings", "setup", "install",
	"backup", "backups", "old", "new", "test", "dev", "staging", "debug",
	"status", "health", "healthz", "metrics", "actuator", "info",
	"robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
	"env", ".env", ".git/config", ".git/HEAD", ".svn/entries",
	"phpinfo.php", "server-status", "server-info", "wp-admin", "wp-login.php",
	"user", "users", "account", "profile", "register", "signup",
	"upload", "uploads", "files", "download", "downloads", "assets",
	"static", "public", "private", "internal", "console", "manage",
	"db", "database", "sql", "phpmyadmin", "adminer", "redis",
	"docs", "documentation", "help", "support", "readme", "readme.md",
	"tmp", "temp", "cache", "logs", "log", "error", "errors",
}

var defaultExtensions = []string{"php", "json", "bak", "old", "zip", "txt"}

func DefaultWords() []string {
	out := make([]string, len(defaultWords))
	copy(out, defaultWords)
	return out
}

func DefaultExtensions() []string {
	out := make([]string, len(defaultExtensions))
	copy(out, defaultExtensions)
	return out
}

var technologyWords = map[string][]string{
	"wordpress": {"wp-admin", "wp-login.php", "wp-content", "wp-json", "wp-config.php.bak"},
	"drupal":    {"user/login", "admin", "sites/default/settings.php", "CHANGELOG.txt"},
	"joomla":    {"administrator", "configuration.php", "administrator/index.php"},
	"jenkins":   {"login", "script", "manage", "systemInfo", "asynchPeople"},
	"gitlab":    {"users/sign_in", "explore", "help", "api/v4/version"},
	"tomcat":    {"manager/html", "host-manager/html", "examples", "docs"},
	"grafana":   {"login", "api/health", "api/datasources"},
	"kibana":    {"app/kibana", "api/status", "login"},
}

func WordsForTechnologies(products []string) []string {
	seen := map[string]bool{}
	out := DefaultWords()
	for _, w := range out {
		seen[w] = true
	}
	for _, product := range products {
		extra, ok := technologyWords[normalizeProduct(product)]
		if !ok {
			continue
		}
		for _, w := range extra {
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
	}
	return out
}

func normalizeProduct(value string) string {
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			out = append(out, c)
		}
	}
	return string(out)
}
