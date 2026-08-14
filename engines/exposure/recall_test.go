package exposure

import "testing"

func TestHardenedSignaturesStillDetectRealFiles(t *testing.T) {
	set, err := LoadSignatures()
	if err != nil {
		t.Fatal(err)
	}
	real := map[string]string{
		"wp-config-backup":        "<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_PASSWORD', 's3cret');\n",
		"config-json":             `{"host":"db","port":5432,"password":"realpassw0rd123"}`,
		"my-cnf":                  "[client]\nuser=root\npassword=secretpass\n",
		"appsettings":             `{"ConnectionStrings":{"DefaultConnection":"Server=x;Password=y"}}`,
		"application-properties":  "server.port=8080\nspring.datasource.password=secret\n",
		"dockerignore":            "node_modules\n.git\n*.log\nDockerfile\n",
		"gitignore":               "node_modules/\n.env\n__pycache__/\n*.pyc\n",
		"git-config":              "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = x\n",
		"env-file":                "APP_ENV=production\nDB_PASSWORD=secret\nAPP_KEY=base64:abc\n",
		"aws-credentials":         "[default]\naws_access_key_id = AKIAXXXX\naws_secret_access_key = yyyy\n",
		"rails-database-yml":      "default: &default\n  adapter: postgresql\n  password: s3cret\nproduction:\n  <<: *default\n",
		"git-logs-head":           "0000000000000000000000000000000000000000 3a1f9c2b4e6d8a0c2e4f6a8b0d2f4c6e8a0b2d4f Dev <d@x.io> 1700000000 +0000\tcommit (initial)\n",
		"elmah-axd":               "<html><body><h1>Error Log for MyApp</h1><table>ELMAH error details</table></body></html>",
		"trace-axd":               "<html><body><span>Application Trace</span><b>Request Details</b>Session Id: abc</body></html>",
		"sublime-sftp-config":     `{"type":"sftp","host":"1.2.3.4","user":"root","password":"pw","upload_on_save":true,"connect_timeout":30}`,
		"vscode-sftp-json":        `{"name":"srv","host":"1.2.3.4","username":"root","password":"pw","uploadOnSave":true,"downloadOnOpen":false}`,
		"joomla-config-bak":       "<?php\nclass JConfig {\n  public $password = 'dbpass';\n  public $secret = 'AbCdEf';\n}\n",
		"rails-secrets-yml":       "production:\n  secret_key_base: 0a1b2c3d4e5f6789abcdef\n",
		"jenkins-credentials-xml": "<?xml version='1.1'?>\n<com.cloudbees.plugins.credentials.SystemCredentialsProvider><passwordHash>x</passwordHash></com.cloudbees.plugins.credentials.SystemCredentialsProvider>",
		"idea-datasources":        `<component><data-source name="db"><jdbc-url>jdbc:mysql://h/db</jdbc-url></data-source></component>`,
	}
	sigByID := map[string]compiledSignature{}
	for _, s := range set.signatures {
		sigByID[s.ID] = s
	}
	for id, body := range real {
		sig, ok := sigByID[id]
		if !ok {
			t.Fatalf("signature %q not found", id)
		}
		if _, matched := sig.matches([]byte(body)); !matched {
			t.Fatalf("RECALL FAIL: hardened signature %q no longer matches real file content", id)
		}
	}
}
