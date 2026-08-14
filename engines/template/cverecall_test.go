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

func TestServiceExposureTemplatesDetectRealResponses(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Template{}
	for _, tmpl := range set.Templates {
		byID[tmpl.ID] = tmpl
	}
	cases := map[string]responseView{
		"solr-admin-exposure":         newResponseView(200, []byte(`{"responseHeader":{"status":0},"lucene":{"solr-spec-version":"8.11.1"},"solr_home":"/var/solr/data"}`), nil),
		"docker-api-exposure":         newResponseView(200, []byte(`{"Platform":{"Name":"Docker Engine"},"ApiVersion":"1.41","GoVersion":"go1.16.15","Os":"linux"}`), nil),
		"kibana-app-exposure":         newResponseView(200, []byte(`<html><head><kbn-injected-metadata data='{"version":"7.10.0"}'></kbn-injected-metadata></head></html>`), nil),
		"prometheus-metrics-exposure": newResponseView(200, []byte("# HELP go_goroutines Number of goroutines.\n# TYPE go_goroutines gauge\ngo_goroutines 24\n"), nil),
		"etcd-keys-exposure":          newResponseView(200, []byte(`{"action":"get","node":{"dir":true,"nodes":[{"key":"/db","value":"secret"}]}}`), nil),
		"consul-agent-exposure":       newResponseView(200, []byte(`{"Config":{"NodeName":"web-1","Datacenter":"dc1","Server":true}}`), nil),
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
			t.Fatalf("RECALL FAIL: service-exposure template %q does not detect a real service response", id)
		}
	}
}

func TestKEVTemplatesDetectRealSurfaces(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Template{}
	for _, tmpl := range set.Templates {
		byID[tmpl.ID] = tmpl
	}
	soapFault := `<?xml version='1.0' encoding='UTF-8'?><S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"><S:Body><S:Fault><faultstring>weblogic.wsee.wstx.wsat.CoordinatorPortType</faultstring></S:Fault></S:Body></S:Envelope>`
	cases := map[string]responseView{
		"cve-2017-10271-weblogic-wsat":    newResponseView(500, []byte(soapFault), nil),
		"cve-2019-2725-weblogic-async":    newResponseView(500, []byte(soapFault), nil),
		"cve-2023-26360-coldfusion-admin": newResponseView(200, []byte(`<html><head><title>ColdFusion Administrator Login</title></head><body>Adobe ColdFusion</body></html>`), nil),
		"cve-2023-27350-papercut-admin":   newResponseView(200, []byte(`<html><head><meta name="csrf-token" content="x"></head><body>PaperCut MF Admin</body></html>`), nil),
		"cve-2024-36401-geoserver":        newResponseView(200, []byte(`<html><body>GeoServer Configuration powered by org.geoserver.web</body></html>`), nil),
		"cve-2023-4966-citrix-bleed":      newResponseView(200, []byte(`<html><body>NetScaler Gateway logon _ctxstxt_ portal</body></html>`), nil),
		"cve-2022-40684-fortios-login":    newResponseView(200, []byte(`<html><script>var fgt_lang='en'; function logincheck(){}</script></html>`), nil),
		"cve-2021-22205-gitlab-signin":    newResponseView(200, []byte(`<html><body><script>gon.gitlab_url="https://x";</script>GitLab Community Edition</body></html>`), nil),
		"cve-2023-42793-teamcity-login":   newResponseView(200, []byte(`<html><head><title>Log in to TeamCity</title></head><body>JetBrains TeamCity</body></html>`), nil),
		"cve-2023-22515-confluence-setup": newResponseView(200, []byte(`<html><body>com.atlassian.confluence context Confluence setup</body></html>`), nil),
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
			t.Fatalf("RECALL FAIL: KEV template %q does not detect its real vulnerable surface", id)
		}
	}
}

func TestKEVTemplatesBatch2DetectRealSurfaces(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Template{}
	for _, tmpl := range set.Templates {
		byID[tmpl.ID] = tmpl
	}
	cases := map[string]responseView{
		"cve-2021-26855-exchange-owa":          newResponseView(200, []byte(`<html><head><title>Outlook Web App</title></head><body><form id="logonForm">OwaPage exchangecookie</form></body></html>`), nil),
		"cve-2021-22005-vcenter":               newResponseView(200, []byte(`<html><body>VMware vSphere - vSphere Client</body></html>`), nil),
		"cve-2023-46805-ivanti-connect-secure": newResponseView(200, []byte(`<html><body>Ivanti Connect Secure DSSignInURL Pulse Secure DSSignInBanner</body></html>`), nil),
		"cve-2022-46169-cacti":                 newResponseView(200, []byte(`<html><body>The Cacti Group auth_login.php cacti_version 1.2.22</body></html>`), nil),
		"cve-2023-38646-metabase":              newResponseView(200, []byte(`{"setup-token":"249fa03d","engines":{"h2":{}},"report-timezone":"UTC"}`), nil),
		"cve-2024-1709-screenconnect":          newResponseView(200, []byte(`<html><body>ScreenConnect by ConnectWise scScriptData Elsinore Technologies</body></html>`), nil),
		"cve-2023-49070-ofbiz":                 newResponseView(200, []byte(`<html><body>Apache OFBiz org.apache.ofbiz OFBiz.Visitor</body></html>`), nil),
		"cve-2019-0604-sharepoint":             newResponseView(200, []byte(`<html><body>SharePoint _spPageContextInfo SP.Runtime</body></html>`), nil),
		"cve-2022-27925-zimbra":                newResponseView(200, []byte(`<html><body>Zimbra ZmLogin zimbraLoginRedirect zimbraBuildVersion</body></html>`), nil),
		"cve-2023-35078-ivanti-epmm":           newResponseView(200, []byte(`<html><body>MobileIron Ivanti EPMM corePropertyBundle mifs_home</body></html>`), nil),
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
			t.Fatalf("RECALL FAIL: KEV template %q does not detect its real vulnerable surface", id)
		}
	}
}

func TestKEVTemplatesBatch3DetectRealSurfaces(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Template{}
	for _, tmpl := range set.Templates {
		byID[tmpl.ID] = tmpl
	}
	cases := map[string]responseView{
		"cve-2022-1388-f5-bigip":                    newResponseView(200, []byte(`<html><body>BIG-IP by F5 Networks - logmein.html</body></html>`), nil),
		"cve-2024-3400-globalprotect":               newResponseView(200, []byte(`<html><body>GlobalProtect Portal PanGlobalProtect</body></html>`), nil),
		"cve-2023-49103-owncloud-graphapi":          newResponseView(200, []byte(`<html><body>phpinfo() PHP Version 7.4.3 PHP Extension OWNCLOUD_ROOT</body></html>`), nil),
		"cve-2024-4040-crushftp":                    newResponseView(200, []byte(`<html><body>CrushFTP by Ben Spink c2s.jar</body></html>`), nil),
		"cve-2022-22954-vmware-workspace-one":       newResponseView(200, []byte(`<html><body>VMware Identity Workspace ONE vIDM horizonInstanceId</body></html>`), nil),
		"cve-2021-40539-manageengine-adselfservice": newResponseView(200, []byte(`<html><body>ManageEngine ADSelfService Plus by Zoho Corporation</body></html>`), nil),
		"cve-2017-12149-jboss-invoker":              newResponseView(500, []byte(`org.jboss.invocation.MarshalledInvocation java.io.ObjectInputStream`), nil),
		"cve-2021-43798-grafana-traversal":          newResponseView(200, []byte(`<html><body>grafanaBootData Grafana "commit":"a1b" "database":"ok"</body></html>`), nil),
		"cve-2024-40766-sonicwall":                  newResponseView(200, []byte(`<html><body>SonicWall NSA SSL-VPN portal</body></html>`), nil),
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
			t.Fatalf("RECALL FAIL: KEV template %q does not detect its real vulnerable surface", id)
		}
	}
}

func TestKEVTemplatesBatch4DetectRealSurfaces(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Template{}
	for _, tmpl := range set.Templates {
		byID[tmpl.ID] = tmpl
	}
	cases := map[string]responseView{
		"cve-2023-23752-joomla-config": newResponseView(200, []byte(`{"data":[{"type":"application","attributes":{"sitename":"x","dbtype":"mysqli","secret":"abc"}}],"links":{"self":"https://jsonapi.org"}}`), nil),
		"cve-2023-28432-minio-leak":    newResponseView(200, []byte(`{"MinioEndpoints":[],"MinioEnv":{"MINIO_ROOT_USER":"admin","MINIO_ROOT_PASSWORD":"secret"}}`), nil),
		"cve-2023-27524-superset":      newResponseView(200, []byte(`<html><body>Superset superset-frontend appbuilder csrf_token</body></html>`), nil),
		"cve-2018-20062-thinkphp":      newResponseView(200, []byte(`<html><body>ThinkPHP topthink Fast &amp; Simple OOP PHP think\app</body></html>`), nil),
		"cve-2019-16097-harbor":        newResponseView(200, []byte(`<html><body>Harbor harbor-app with_notary registry_url</body></html>`), nil),
		"cve-2022-24348-argocd":        newResponseView(200, []byte(`<html><body>Argo CD argocd __CONFIG__ "Version":"v2.3.0"</body></html>`), nil),
		"cve-2022-23131-zabbix-saml":   newResponseView(200, []byte(`<html><body>Zabbix SIA zbx_session Zabbix saml</body></html>`), nil),
		"cve-2020-11978-airflow":       newResponseView(200, []byte(`<html><body>Apache Airflow airflow-webserver DAGs</body></html>`), nil),
		"cve-2022-36804-bitbucket":     newResponseView(200, []byte(`<html><body>Bitbucket com.atlassian.bitbucket stash- "state":"RUNNING"</body></html>`), nil),
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
			t.Fatalf("RECALL FAIL: template %q does not detect its real vulnerable surface", id)
		}
	}
}

func TestKEVTemplatesBatch5DetectRealSurfaces(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Template{}
	for _, tmpl := range set.Templates {
		byID[tmpl.ID] = tmpl
	}
	cases := map[string]responseView{
		"cve-2022-29464-wso2-fileupload": newResponseView(200, []byte(`<html><body>WSO2 wso2carbon carbon-kernel identityServerEndpointContextURL</body></html>`), nil),
		"cve-2020-7961-liferay":          newResponseView(200, []byte(`<html><body>Liferay liferay-portal com.liferay Portlet</body></html>`), nil),
		"cve-2019-18935-telerik-ui":      newResponseView(200, []byte(`{ "message" : "RadAsyncUpload handler is registered succesfully, however http compression rauPostData" }`), nil),
		"cve-2021-25296-nagios-xi":       newResponseView(200, []byte(`<html><body>Nagios XI by Nagios Enterprises xi_version</body></html>`), nil),
		"cve-2018-9276-prtg":             newResponseView(200, []byte(`<html><body>PRTG Network Monitor by Paessler PRTG/22</body></html>`), nil),
		"cve-2022-35914-glpi":            newResponseView(200, []byte(`<html><body>GLPI glpi_csrf_token by Teclib</body></html>`), nil),
		"cve-2021-25646-druid":           newResponseView(200, []byte(`<html><body>Apache Druid druid-console clusterOverview</body></html>`), nil),
		"cve-2022-1040-sophos-firewall":  newResponseView(200, []byte(`<html><body>Sophos SF-OS csc.sophos Cyberoam</body></html>`), nil),
		"cve-2021-42237-sitecore":        newResponseView(200, []byte(`<html><body>Sitecore.NET sc_site Sitecore CMS <version>9.3</version></body></html>`), nil),
		"cve-2022-21587-oracle-ebs":      newResponseView(200, []byte(`<html><body>Oracle Applications E-Business Suite AppsLoginPage oracle.apps</body></html>`), nil),
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
			t.Fatalf("RECALL FAIL: template %q does not detect its real vulnerable surface", id)
		}
	}
}

func TestKEVTemplatesBatch6DetectRealSurfaces(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Template{}
	for _, tmpl := range set.Templates {
		byID[tmpl.ID] = tmpl
	}
	cases := map[string]responseView{
		"cve-2023-0669-goanywhere-mft":    newResponseView(200, []byte(`<html><body>GoAnywhere by Fortra (HelpSystems) Managed File Transfer</body></html>`), nil),
		"cve-2024-24919-checkpoint-vpn":   newResponseView(200, []byte(`<html><body>Check Point SSL Network Extender cpcgi CvpnHeaderName</body></html>`), nil),
		"cve-2023-38035-ivanti-sentry":    newResponseView(200, []byte(`<html><body>MobileIron Sentry System Manager MICSLogService</body></html>`), nil),
		"cve-2024-28995-solarwinds-servu": newResponseView(200, []byte(`<html><body>Serv-U by SolarWinds RhinoSoft Serv-U-Session-ID</body></html>`), nil),
		"cve-2024-31982-xwiki":            newResponseView(200, []byte(`<html><body>XWiki org.xwiki XWiki Enterprise</body></html>`), nil),
		"cve-2024-4885-whatsup-gold":      newResponseView(200, []byte(`<html><body>WhatsUp Gold by Ipswitch Progress WhatsUp</body></html>`), nil),
		"cve-2022-22965-spring4shell":     newResponseView(500, []byte(`<html><body>Whitelabel Error Page org.springframework This application has no explicit mapping</body></html>`), nil),
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
			t.Fatalf("RECALL FAIL: template %q does not detect its real vulnerable surface", id)
		}
	}
}

func TestKEVTemplatesBatch7DetectRealSurfaces(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Template{}
	for _, tmpl := range set.Templates {
		byID[tmpl.ID] = tmpl
	}
	cases := map[string]responseView{
		"cve-2023-20198-cisco-ios-xe":    newResponseView(200, []byte(`<html><body>Cisco Systems IOS-XE webui_login Cisco IOS</body></html>`), nil),
		"cve-2024-23692-rejetto-hfs":     newResponseView(200, []byte(`<html><body>HttpFileServer by Rejetto - HFS 2.3 hfs.js</body></html>`), nil),
		"cve-2023-36845-juniper-jweb":    newResponseView(200, []byte(`<html><body>J-Web by Juniper Networks jweb-manager SRX</body></html>`), nil),
		"cve-2020-3452-cisco-asa":        newResponseView(200, []byte(`<html><body>SSL VPN Service by Cisco Systems, Inc AnyConnect webvpnlogin</body></html>`), nil),
		"cve-2024-27348-hugegraph":       newResponseView(200, []byte(`{"versions":{"version":"0.0.1","core":"1.0.0","gremlin":"3.5.1"}}`), nil),
		"cve-2024-1212-kemp-loadmaster":  newResponseView(200, []byte(`<html><body>LoadMaster by KEMP Technologies lmadmin</body></html>`), nil),
		"cve-2023-23368-qnap-qts":        newResponseView(200, []byte(`<html><body>QNAP QTS quTShero QNAP Systems</body></html>`), nil),
		"cve-2022-26134-confluence-ognl": newResponseView(200, []byte(`<html><body>com.atlassian.confluence confluence-context-path Confluence atlassian-token</body></html>`), nil),
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
			t.Fatalf("RECALL FAIL: template %q does not detect its real vulnerable surface", id)
		}
	}
}
