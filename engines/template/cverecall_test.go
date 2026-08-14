package template

import "testing"

func TestCVETemplatesDetectRealVulnResponses(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Template{}
	for _, tmpl := range set.Templates {
		byID[tmpl.ID] = tmpl
	}
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	cases := map[string]responseView{
		"cve-2021-41773-apache-traversal": newResponseView(200, []byte(passwd), nil),
		"cve-2021-42013-apache-traversal": newResponseView(200, []byte(passwd), nil),
		"cve-2019-11510-pulse":            newResponseView(200, []byte(passwd), nil),
		"generic-lfi-passwd":              newResponseView(200, []byte(passwd), nil),
		"cve-2018-13379-fortinet":         newResponseView(200, []byte("var fgt_lang=...\nsslvpn_websession data"), nil),
		"cve-2019-19781-citrix-traversal": newResponseView(200, []byte("[global]\n  encrypt passwords = yes\n  name resolve order = lmhosts wins\n"), nil),
		"cve-2021-3129-laravel-ignition":  newResponseView(200, []byte(`{"can_execute_commands":true,"config":{"editor":"phpstorm"}}`), nil),
		"cve-2020-14882-weblogic-console": newResponseView(200, []byte(`<html><head><title>WebLogic Server Administration Console</title></head><body>Console</body></html>`), nil),
		"cve-2023-34362-moveit-transfer":  newResponseView(200, []byte(`<html><body>MOVEit Transfer &copy; Progress Software</body></html>`), nil),
		"jenkins-instance-exposure":       newResponseView(200, []byte(`<html>Dashboard</html>`), map[string]string{"X-Jenkins": "2.401.1"}),
		"elasticsearch-unauth-exposure":   newResponseView(200, []byte(`{"name":"node-1","cluster_name":"es","version":{"number":"6.8.0","lucene_version":"7.7.0"}}`), nil),
	}
	for id, view := range cases {
		tmpl, ok := byID[id]
		if !ok {
			t.Fatalf("template %q missing", id)
		}
		matched := false
		for _, req := range tmpl.Requests {
			if req.matches(view) {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("RECALL FAIL: CVE template %q does not detect a real exploit response", id)
		}
	}
}
