package policy

import "testing"

func TestWatchOnlyNeverSendsTraffic(t *testing.T) {
	active := []ActionClass{ActionDNSResolve, ActionTCPConnect, ActionHTTPHead, ActionHTTPGet, ActionTLSInspect, ActionServiceProbe, ActionTechFingerprint, ActionContentDiscovery, ActionVulnTemplate, ActionNSEScript, ActionCredentialValidate, ActionSecretValidate}
	for _, a := range active {
		if d := Decide(ModeWatchOnly, a, true); d.Allowed {
			t.Fatalf("watchonly must never allow %s", a)
		}
	}
	if d := Decide(ModeWatchOnly, ActionPassiveIntel, false); !d.Allowed {
		t.Fatalf("watchonly must allow passive enrichment: %v", d.Reasons)
	}
}

func TestPassiveBlocksActive(t *testing.T) {
	if d := Decide(ModePassive, ActionTCPConnect, true); d.Allowed {
		t.Fatal("passive mode must block tcpconnect even with grants")
	}
}

func TestSafeActiveBlocksAuthorizedTestActions(t *testing.T) {
	for _, a := range []ActionClass{ActionContentDiscovery, ActionVulnTemplate, ActionNSEScript, ActionSecretValidate} {
		if d := Decide(ModeSafeActive, a, true); d.Allowed {
			t.Fatalf("safeactive must block %s", a)
		}
	}
	if d := Decide(ModeSafeActive, ActionDNSResolve, false); !d.Allowed {
		t.Fatal("safeactive must allow dnsresolve")
	}
}

func TestAuthorizedTestRequiresExplicitGrants(t *testing.T) {
	if d := Decide(ModeAuthorizedTest, ActionVulnTemplate, false); d.Allowed {
		t.Fatal("vulntemplate without explicit grant must be denied")
	}
	if d := Decide(ModeAuthorizedTest, ActionVulnTemplate, true); !d.Allowed {
		t.Fatalf("granted vulntemplate must be allowed: %v", d.Reasons)
	}
	if d := Decide(ModeAuthorizedTest, ActionCredentialValidate, false); d.Allowed {
		t.Fatal("credential validation without grant must be denied")
	}
}

func TestFailClosedOnUnknown(t *testing.T) {
	if d := Decide(Mode("bogus"), ActionPassiveIntel, true); d.Allowed {
		t.Fatal("unknown mode must fail closed")
	}
	if _, err := ParseAction("dosattack"); err == nil {
		t.Fatal("unknown action must fail to parse")
	}
	if _, err := ParseMode("yolo"); err == nil {
		t.Fatal("unknown mode must fail to parse")
	}
}

func TestModeRanking(t *testing.T) {
	if !ModeAuthorizedTest.Allows(ModeSafeActive) {
		t.Fatal("authorizedtest must allow safeactive actions")
	}
	if ModePassive.Allows(ModeSafeActive) {
		t.Fatal("passive must not allow safeactive actions")
	}
}
