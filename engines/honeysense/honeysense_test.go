package honeysense

import "testing"

func TestBenignHostScoresLow(t *testing.T) {
	v := Score(Signals{
		OpenPorts:       []int{22, 443},
		Banners:         map[int]string{22: "SSH-2.0-OpenSSH_9.6", 443: "HTTP"},
		TLSSubjects:     map[int]string{443: "example.com"},
		ResponseTimesMS: []int64{120, 340, 95, 210, 150},
	})
	if v.Score >= 0.4 {
		t.Fatalf("benign host must score low, got %f (%+v)", v.Score, v.Components)
	}
	if v.Recommendation != "normal" {
		t.Fatalf("recommendation must be normal, got %s", v.Recommendation)
	}
}

func TestDenseHoneypotScoresHigh(t *testing.T) {
	ports := []int{}
	banners := map[int]string{}
	for i := 0; i < 60; i++ {
		ports = append(ports, 1000+i)
		banners[1000+i] = "SSH-2.0-OpenSSH_7.4"
	}
	v := Score(Signals{
		OpenPorts:            ports,
		Banners:              banners,
		ResponseTimesMS:      []int64{100, 100, 101, 100, 100, 101},
		ProviderDisagreement: true,
		ConnectionAnomalies:  3,
		KnownHoneypotBanner:  true,
		SyntheticErrors:      3,
	})
	if v.Score < 0.65 {
		t.Fatalf("dense honeypot must score high, got %f", v.Score)
	}
	if v.Recommendation != "reduce-intensity" || !v.RequiresReview {
		t.Fatalf("high score must reduce intensity and require review: %+v", v)
	}
}

func TestEveryComponentStored(t *testing.T) {
	v := Score(Signals{OpenPorts: []int{80}})
	if len(v.Components) != 10 {
		t.Fatalf("all 10 signal components must be stored, got %d", len(v.Components))
	}
	for _, c := range v.Components {
		if c.Weight <= 0 {
			t.Fatalf("every component must carry a positive weight: %+v", c)
		}
	}
}

func TestProtocolContradiction(t *testing.T) {
	v := Score(Signals{
		OpenPorts: []int{22, 443},
		Banners:   map[int]string{22: "mysql native", 443: "SSH-2.0-OpenSSH"},
	})
	found := false
	for _, c := range v.Components {
		if c.Name == "protocol-contradiction" {
			found = true
			if c.Score == 0 {
				t.Fatal("contradicting banners must score above zero")
			}
		}
	}
	if !found {
		t.Fatal("protocol-contradiction component missing")
	}
}

func TestClassicHoneypotIsFlagged(t *testing.T) {
	banners := map[int]string{}
	var ports []int
	for p := 9001; p <= 9025; p++ {
		ports = append(ports, p)
		banners[p] = "SSH-2.0-OpenSSH_7.4"
	}
	v := Score(Signals{OpenPorts: ports, Banners: banners})
	if v.Score < 0.65 || !v.RequiresReview {
		t.Fatalf("25 ports with identical banners is a classic honeypot and must be flagged, got %.2f (review=%v)", v.Score, v.RequiresReview)
	}
}

func TestNormalHostNotFlagged(t *testing.T) {
	v := Score(Signals{
		OpenPorts: []int{80, 443, 22},
		Banners:   map[int]string{22: "SSH-2.0-OpenSSH_9.6", 80: "Apache/2.4.62", 443: "Apache/2.4.62"},
	})
	if v.Score >= 0.4 {
		t.Fatalf("a normal 3-port host must not be flagged, got %.2f", v.Score)
	}
}
