package policy

import "fmt"

type Decision struct {
	Allowed bool     `json:"allowed"`
	Reasons []string `json:"reasons"`
}

func deny(reason string) Decision {
	return Decision{Allowed: false, Reasons: []string{reason}}
}

func Decide(mode Mode, action ActionClass, classGranted bool) Decision {
	if !mode.Valid() {
		return deny(fmt.Sprintf("unknown mode %q", mode))
	}
	minMode, ok := actionMinMode[action]
	if !ok {
		return deny(fmt.Sprintf("unknown action class %q", action))
	}
	if !mode.Allows(minMode) {
		return deny(fmt.Sprintf("mode %s does not permit %s (requires %s)", mode, action, minMode))
	}
	if grantRequired[action] && !classGranted {
		return deny(fmt.Sprintf("action %s requires an explicit scope grant", action))
	}
	return Decision{Allowed: true, Reasons: []string{fmt.Sprintf("mode %s permits %s", mode, action)}}
}
