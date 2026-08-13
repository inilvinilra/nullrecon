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
	total := 0.0
	for _, c := range v.Components {
		total += c.Weight
	}
	if total < 0.99 || total > 1.01 {
		t.Fatalf("component weights must sum to 1, got %f", total)
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
