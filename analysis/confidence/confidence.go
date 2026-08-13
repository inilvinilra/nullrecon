package confidence

import "github.com/nullrecon/nullrecon/domain/finding"

type Model struct {
	weightParse       float64
	weightOwnership   float64
	weightFreshness   float64
	weightFingerprint float64
	weightVersion     float64
	weightPrereq      float64
	weightCrossSource float64
	weightActive      float64
}

func DefaultModel() Model {
	return Model{
		weightParse:       0.05,
		weightOwnership:   0.20,
		weightFreshness:   0.10,
		weightFingerprint: 0.15,
		weightVersion:     0.15,
		weightPrereq:      0.10,
		weightCrossSource: 0.10,
		weightActive:      0.15,
	}
}

type Decision struct {
	Value float64       `json:"value"`
	State finding.State `json:"state"`
	Gates []string      `json:"gates,omitempty"`
}

func (m Model) Decide(c finding.Confidence, mandatory []string) Decision {
	base := m.weightParse*clamp(c.Parse) +
		m.weightOwnership*clamp(c.Ownership) +
		m.weightFreshness*clamp(c.Freshness) +
		m.weightFingerprint*clamp(c.Fingerprint) +
		m.weightVersion*clamp(c.Version) +
		m.weightPrereq*clamp(c.Prerequisite) +
		m.weightCrossSource*clamp(c.CrossSource) +
		m.weightActive*clamp(c.ActiveVerification)

	base -= 0.5*clamp(c.DeceptionPenalty) +
		0.3*clamp(c.SharedInfraPenalty) +
		0.2*clamp(c.GatewayPenalty) +
		0.2*clamp(c.StalenessPenalty)

	value := clamp(base)
	var gates []string

	for _, name := range mandatory {
		if componentValue(c, name) <= 0 {
			value = min(value, 0.25)
			gates = append(gates, "mandatory:"+name+":missing")
		}
	}
	if clamp(c.Ownership) < 0.4 {
		value = min(value, 0.5)
		gates = append(gates, "ownership-floor")
	}
	if clamp(c.DeceptionPenalty) >= 0.5 {
		value = min(value, 0.4)
		gates = append(gates, "deception-cap")
	}

	state := stateForValue(value)
	if state == finding.StateConfirmed && clamp(c.ActiveVerification) < 0.8 && clamp(c.CrossSource) < 0.5 {
		state = finding.StateLikely
		gates = append(gates, "no-passive-confirm")
	}
	return Decision{Value: round2(value), State: state, Gates: gates}
}

func stateForValue(value float64) finding.State {
	switch {
	case value >= 0.85:
		return finding.StateConfirmed
	case value >= 0.6:
		return finding.StateLikely
	case value >= 0.4:
		return finding.StatePotential
	case value >= 0.2:
		return finding.StateInformational
	default:
		return finding.StateNeedsReview
	}
}

func componentValue(c finding.Confidence, name string) float64 {
	switch name {
	case "parse":
		return c.Parse
	case "ownership":
		return c.Ownership
	case "freshness":
		return c.Freshness
	case "fingerprint":
		return c.Fingerprint
	case "version":
		return c.Version
	case "prerequisite":
		return c.Prerequisite
	case "crossSource":
		return c.CrossSource
	case "activeVerification":
		return c.ActiveVerification
	}
	return 0
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}
