package policy

import "fmt"

type ActionClass string

const (
	ActionPassiveIntel       ActionClass = "passiveintel"
	ActionStoreEnrich        ActionClass = "storeenrich"
	ActionDNSResolve         ActionClass = "dnsresolve"
	ActionTCPConnect         ActionClass = "tcpconnect"
	ActionHTTPHead           ActionClass = "httphead"
	ActionHTTPGet            ActionClass = "httpget"
	ActionTLSInspect         ActionClass = "tlsinspect"
	ActionServiceProbe       ActionClass = "serviceprobe"
	ActionTechFingerprint    ActionClass = "techfingerprint"
	ActionPortScanDeep       ActionClass = "portscandeep"
	ActionContentDiscovery   ActionClass = "contentdiscovery"
	ActionVulnTemplate       ActionClass = "vulntemplate"
	ActionNSEScript          ActionClass = "nsescript"
	ActionVulnVerify         ActionClass = "vulnverify"
	ActionCredentialValidate ActionClass = "credentialvalidate"
	ActionSecretValidate     ActionClass = "secretvalidate"
)

var actionMinMode = map[ActionClass]Mode{
	ActionPassiveIntel:       ModeWatchOnly,
	ActionStoreEnrich:        ModeWatchOnly,
	ActionDNSResolve:         ModeSafeActive,
	ActionTCPConnect:         ModeSafeActive,
	ActionHTTPHead:           ModeSafeActive,
	ActionHTTPGet:            ModeSafeActive,
	ActionTLSInspect:         ModeSafeActive,
	ActionServiceProbe:       ModeSafeActive,
	ActionTechFingerprint:    ModeSafeActive,
	ActionPortScanDeep:       ModeAuthorizedTest,
	ActionContentDiscovery:   ModeAuthorizedTest,
	ActionVulnTemplate:       ModeAuthorizedTest,
	ActionNSEScript:          ModeAuthorizedTest,
	ActionVulnVerify:         ModeAuthorizedTest,
	ActionCredentialValidate: ModeAuthorizedTest,
	ActionSecretValidate:     ModeAuthorizedTest,
}

var grantRequired = map[ActionClass]bool{
	ActionPortScanDeep:       true,
	ActionContentDiscovery:   true,
	ActionVulnTemplate:       true,
	ActionNSEScript:          true,
	ActionVulnVerify:         true,
	ActionCredentialValidate: true,
	ActionSecretValidate:     true,
}

func ParseAction(value string) (ActionClass, error) {
	a := ActionClass(value)
	if _, ok := actionMinMode[a]; !ok {
		return "", fmt.Errorf("policy: unknown action class %q", value)
	}
	return a, nil
}

func (a ActionClass) MinMode() Mode {
	return actionMinMode[a]
}

func (a ActionClass) NeedsExplicitGrant() bool {
	return grantRequired[a]
}
