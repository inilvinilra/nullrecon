package template

import "testing"

func TestDSLEvaluator(t *testing.T) {
	v := newResponseView(200, []byte("<html>SquirrelMail version 1.4.22 login</html>"), map[string]string{"Content-Type": "text/html"})
	cases := map[string]bool{
		`status_code == 200`:                                   true,
		`status_code == 404`:                                   false,
		`contains(body, "SquirrelMail")`:                       true,
		`contains(tolower(body), "squirrelmail")`:              true,
		`contains(body, "SquirrelMail") && status_code == 200`: true,
		`contains(body, "Nope") || contains(body, "login")`:    true,
		`contains_all(body, "SquirrelMail", "login")`:          true,
		`contains_all(body, "SquirrelMail", "missing")`:        false,
		`contains_any(body, "x", "login")`:                     true,
		`!contains(body, "<HTML")`:                             true,
		`contains(content_type, "text/html")`:                  true,
		`len(body) > 10`:                                       true,
		`compare_versions("1.4.22", ">= 1.0", "< 2.0")`:        true,
		`compare_versions("3.0", "< 2.0")`:                     false,
	}
	for expr, want := range cases {
		got, ok := evalDSL(expr, v)
		if !ok {
			t.Fatalf("parse failed: %q", expr)
		}
		if got != want {
			t.Fatalf("%q => %v, want %v", expr, got, want)
		}
	}
}
