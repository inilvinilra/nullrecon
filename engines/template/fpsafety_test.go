package template

import "testing"

func decoyResponses() []responseView {
	genericHTML := `<!doctype html><html><head><title>Welcome</title></head><body>
<h1>It works!</h1><p>Default page. Nothing to see here.</p>
<a href="/home">home</a><script src="/app.js"></script></body></html>`
	soft404 := `<!DOCTYPE html><html><head><title>404 Not Found</title></head><body>
<h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>`
	loginPage := `<html><head><title>Login</title></head><body><form><input name="user"><input name="pass" type="password"></form></body></html>`
	emptyish := `<html><body></body></html>`
	views := []responseView{
		newResponseView(200, []byte(genericHTML), map[string]string{"Content-Type": "text/html"}),
		newResponseView(200, []byte(soft404), map[string]string{"Content-Type": "text/html"}),
		newResponseView(200, []byte(loginPage), map[string]string{"Content-Type": "text/html", "Server": "nginx"}),
		newResponseView(200, []byte(emptyish), map[string]string{"Content-Type": "text/html"}),
		newResponseView(403, []byte(genericHTML), map[string]string{"Content-Type": "text/html"}),
		newResponseView(200, []byte("<html>random marketing content about our products and services</html>"), map[string]string{}),
		newResponseView(404, []byte(soft404), map[string]string{"Content-Type": "text/html", "Server": "Apache"}),
		newResponseView(500, []byte(`<html><head><title>500 Internal Server Error</title></head><body><h1>Internal Server Error</h1><p>The server encountered an internal error and was unable to complete your request.</p></body></html>`), map[string]string{"Content-Type": "text/html"}),
		newResponseView(200, []byte(`{"status":"ok","message":"service healthy","version":"1.2.3"}`), map[string]string{"Content-Type": "application/json"}),
	}
	return views
}

func TestNoTemplateMatchesDecoyResponses(t *testing.T) {
	set, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range decoyResponses() {
		for _, tmpl := range set.Templates {
			for i, req := range tmpl.Requests {
				if tmpl.ID == "server-version-disclosure" && view.headers["server"] != "" {
					continue
				}
				if req.matches(view) {
					t.Fatalf("template %q request %d falsely matched a decoy response (soft-404/generic HTML) - false positive risk; body=%q", tmpl.ID, i, view.body[:min(60, len(view.body))])
				}
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
