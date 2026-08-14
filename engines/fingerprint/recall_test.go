package fingerprint

import "testing"

func TestHardenedCMSRulesStillDetect(t *testing.T) {
	e, err := DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Features{
		"wordpress": {BodySnippet: `<link rel="stylesheet" href="https://x/wp-content/themes/twentytwenty/style.css">`},
		"joomla":    {BodySnippet: `<script src="/media/jui/js/jquery.min.js"></script>`},
		"drupal":    {BodySnippet: `<script src="/sites/all/modules/x/y.js"></script>`},
		"magento":   {BodySnippet: `<link href="/skin/frontend/default/theme/css/styles.css">`},

		"weblogic_server":                       {Headers: map[string]string{"server": "Oracle WebLogic Server 12.2.1.4"}},
		"websphere_application_server":          {Headers: map[string]string{"server": "WebSphere Application Server/8.5"}},
		"glassfish_server":                      {Headers: map[string]string{"server": "GlassFish Server Open Source Edition 4.1"}},
		"wildfly":                               {Headers: map[string]string{"server": "WildFly/26"}},
		"jboss_enterprise_application_platform": {Headers: map[string]string{"x-powered-by": "JBoss-EAP/7"}},
		"coldfusion":                            {Cookies: []string{"CFTOKEN=abc; path=/"}},
		"confluence":                            {Headers: map[string]string{"x-confluence-request-time": "1699999999999"}},
		"sharepoint_server":                     {Headers: map[string]string{"microsoftsharepointteamservices": "16.0.0.10337"}},
		"splunk":                                {Headers: map[string]string{"server": "Splunkd"}},
		"couchdb":                               {Headers: map[string]string{"server": "CouchDB/3.2.1 (Erlang OTP/23)"}},
		"influxdb":                              {Headers: map[string]string{"x-influxdb-version": "1.8.10"}},
		"artifactory":                           {Headers: map[string]string{"x-artifactory-id": "abc123"}},
		"nexus":                                 {Headers: map[string]string{"server": "Nexus/3.37.3-02"}},
		"boa":                                   {Headers: map[string]string{"server": "Boa/0.94.13"}},
		"big-ip":                                {Cookies: []string{"BIGipServerpool_web=1234567890.20480.0000; path=/"}},
		"netscaler":                             {Cookies: []string{"NSC_wtstxanst=abcdef; secure; path=/"}},
		"fortios":                               {Cookies: []string{"SVPNCOOKIE=deadbeef; path=/"}},
		"play_framework":                        {Cookies: []string{"PLAY_SESSION=eyJ...; path=/"}},
		"zabbix":                                {Title: "Zabbix"},
		"python":                                {Headers: map[string]string{"server": "BaseHTTP/0.6 Python/3.14.7"}},
	}
	for product, f := range cases {
		got := e.Apply(f)
		found := false
		for _, tech := range got {
			if tech.Product == product {
				found = true
			}
		}
		if !found {
			t.Fatalf("RECALL FAIL: hardened %s rule no longer detects a real asset-linked page: %+v", product, got)
		}
	}
}
