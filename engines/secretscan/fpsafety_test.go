package secretscan

import "testing"

func TestCommonNoiseIsSuppressed(t *testing.T) {
	set, err := DefaultDetectors()
	if err != nil {
		t.Fatal(err)
	}
	noise := []string{
		`aws_access_key_id = AKIAIOSFODNN7EXAMPLE`,
		`aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
		`api_key = "your_api_key_here"`,
		`api_key = "YOUR_API_KEY"`,
		`password = "changeme"`,
		`password = "xxxxxxxxxxxxxxxx"`,
		`token = "aaaaaaaaaaaaaaaaaaaaaaaa"`,
		`secret = "REPLACE_WITH_YOUR_SECRET"`,
		`# example: api_key=1234567890abcdef1234567890abcdef`,
		`commit 5f3a2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a`,
		`id = "00000000-0000-0000-0000-000000000000"`,
		`href="https://example.com/path/to/page"`,
	}
	for _, line := range noise {
		res := Scan(set, []byte(line), "config")
		if len(res.Candidates) != 0 {
			t.Fatalf("noise line must not yield a confirmed secret: %q -> %+v", line, res.Candidates)
		}
	}
}

func TestRealSecretsStillConfirmed(t *testing.T) {
	set, err := DefaultDetectors()
	if err != nil {
		t.Fatal(err)
	}
	real := "AKIA" + "QYLPZ7K3JX2N4M8R"
	res := Scan(set, []byte("aws_access_key_id = "+real), "config")
	if len(res.Candidates) == 0 {
		t.Fatalf("a real-looking AWS key must still be confirmed after noise filtering")
	}
}
