package registry

type Capability string

const (
	CapAssetSearch        Capability = "assetsearch"
	CapHostLookup         Capability = "hostlookup"
	CapServiceSearch      Capability = "servicesearch"
	CapCertificateSearch  Capability = "certificatesearch"
	CapDNSCurrent         Capability = "dnscurrent"
	CapDNSHistory         Capability = "dnshistory"
	CapDomainLookup       Capability = "domainlookup"
	CapSubdomainSearch    Capability = "subdomainsearch"
	CapLeakSearch         Capability = "leaksearch"
	CapNoiseLookup        Capability = "noiselookup"
	CapURLHistory         Capability = "urlhistory"
	CapURLSubmit          Capability = "urlsubmit"
	CapRepoSearch         Capability = "reposearch"
	CapSecretSignalSearch Capability = "secretsignalsearch"
	CapBreachDomainLookup Capability = "breachdomainlookup"
	CapCVELookup          Capability = "cvelookup"
	CapCPELookup          Capability = "cpelookup"
	CapAdvisoryLookup     Capability = "advisorylookup"
	CapExploitPriority    Capability = "exploitprioritylookup"
	CapUsageLookup        Capability = "usagelookup"
)

func (d Descriptor) Supports(c Capability) bool {
	for _, have := range d.Capabilities {
		if have == c {
			return true
		}
	}
	return false
}
