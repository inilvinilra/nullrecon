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
		"cve-2019-11510-pulse":            newResponseView(200, []byte(passwd), nil),
		"generic-lfi-passwd":              newResponseView(200, []byte(passwd), nil),
		"cve-2018-13379-fortinet":         newResponseView(200, []byte("var fgt_lang=...\nsslvpn_websession data"), nil),
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
