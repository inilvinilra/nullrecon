package exposure

import "testing"

func TestHardenedSignaturesStillDetectRealFiles(t *testing.T) {
	set, err := LoadSignatures()
	if err != nil {
		t.Fatal(err)
	}
	real := map[string]string{
		"wp-config-backup":       "<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_PASSWORD', 's3cret');\n",
		"config-json":            `{"host":"db","port":5432,"password":"realpassw0rd123"}`,
		"my-cnf":                 "[client]\nuser=root\npassword=secretpass\n",
		"appsettings":            `{"ConnectionStrings":{"DefaultConnection":"Server=x;Password=y"}}`,
		"application-properties": "server.port=8080\nspring.datasource.password=secret\n",
		"dockerignore":           "node_modules\n.git\n*.log\nDockerfile\n",
		"gitignore":              "node_modules/\n.env\n__pycache__/\n*.pyc\n",
		"git-config":             "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = x\n",
		"env-file":               "APP_ENV=production\nDB_PASSWORD=secret\nAPP_KEY=base64:abc\n",
		"aws-credentials":        "[default]\naws_access_key_id = AKIAXXXX\naws_secret_access_key = yyyy\n",
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
