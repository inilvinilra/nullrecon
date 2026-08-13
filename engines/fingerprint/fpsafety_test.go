package fingerprint

import "testing"

func TestNoFalseTechOnGenericResponses(t *testing.T) {
	e, err := DefaultEngine()
	if err != nil {
		t.Fatal(err)
	}
	decoys := []Features{
		{Headers: map[string]string{"content-type": "text/html"}, Title: "Welcome", BodySnippet: "<html><body><h1>It works!</h1><p>Default page. Nothing here.</p></body></html>"},
		{Headers: map[string]string{"server": "Zervana/9.9", "content-type": "text/html"}, Title: "404 Not Found", BodySnippet: "<html><body>Not Found</body></html>"},
		{BodySnippet: "random marketing content about our products and services"},
		{Headers: map[string]string{}, Title: "", BodySnippet: ""},
		{BodySnippet: `{"status":"ok","version":"1.2.3"}`},
	}
	for i, f := range decoys {
		got := e.Apply(f)
		if len(got) != 0 {
			t.Fatalf("decoy %d yielded false technology detections: %+v", i, got)
		}
	}
}
