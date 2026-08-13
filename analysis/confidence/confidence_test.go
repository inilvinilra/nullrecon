package confidence

import (
	"testing"

	"github.com/nullrecon/nullrecon/domain/finding"
)

func TestConfirmedRequiresActiveOrCrossSource(t *testing.T) {
	m := DefaultModel()
	c := finding.Confidence{
		Parse:        1,
		Ownership:    1,
		Freshness:    1,
		Fingerprint:  1,
		Version:      1,
		Prerequisite: 1,
		CrossSource:  0,
	}
	d := m.Decide(c, nil)
	if d.State == finding.StateConfirmed {
		t.Fatalf("expected downgrade from confirmed without active/cross-source, got %s (value %.2f)", d.State, d.Value)
	}
}

func TestActiveVerificationConfirms(t *testing.T) {
	m := DefaultModel()
	c := finding.Confidence{
		Parse:              1,
		Ownership:          1,
		Freshness:          1,
		Fingerprint:        1,
		Version:            1,
		Prerequisite:       1,
		CrossSource:        0,
		ActiveVerification: 1,
	}
	d := m.Decide(c, nil)
	if d.State != finding.StateConfirmed {
		t.Fatalf("expected confirmed with full active verification, got %s (value %.2f)", d.State, d.Value)
	}
}

func TestCrossSourceConfirms(t *testing.T) {
	m := DefaultModel()
	c := finding.Confidence{
		Parse:        1,
		Ownership:    1,
		Freshness:    1,
		Fingerprint:  1,
		Version:      1,
		Prerequisite: 1,
		CrossSource:  1,
	}
	d := m.Decide(c, nil)
	if d.State != finding.StateConfirmed {
		t.Fatalf("expected confirmed with cross-source corroboration, got %s (value %.2f)", d.State, d.Value)
	}
}

func TestMandatoryMissingCaps(t *testing.T) {
	m := DefaultModel()
	c := finding.Confidence{
		Parse:              1,
		Ownership:          1,
		Freshness:          1,
		Fingerprint:        0,
		Version:            1,
		Prerequisite:       1,
		ActiveVerification: 1,
	}
	d := m.Decide(c, []string{"fingerprint"})
	if d.Value > 0.25 {
		t.Fatalf("expected mandatory-missing cap at 0.25, got %.2f", d.Value)
	}
	if !hasGate(d.Gates, "mandatory:fingerprint:missing") {
		t.Fatalf("expected mandatory gate, got %v", d.Gates)
	}
}

func TestOwnershipFloor(t *testing.T) {
	m := DefaultModel()
	c := finding.Confidence{
		Parse:              1,
		Ownership:          0.2,
		Freshness:          1,
		Fingerprint:        1,
		Version:            1,
		Prerequisite:       1,
		ActiveVerification: 1,
	}
	d := m.Decide(c, nil)
	if d.Value > 0.5 {
		t.Fatalf("expected ownership floor cap at 0.5, got %.2f", d.Value)
	}
	if !hasGate(d.Gates, "ownership-floor") {
		t.Fatalf("expected ownership-floor gate, got %v", d.Gates)
	}
}

func TestDeceptionCap(t *testing.T) {
	m := DefaultModel()
	c := finding.Confidence{
		Parse:              1,
		Ownership:          1,
		Freshness:          1,
		Fingerprint:        1,
		Version:            1,
		Prerequisite:       1,
		ActiveVerification: 1,
		DeceptionPenalty:   0.8,
	}
	d := m.Decide(c, nil)
	if d.Value > 0.4 {
		t.Fatalf("expected deception cap at 0.4, got %.2f", d.Value)
	}
	if !hasGate(d.Gates, "deception-cap") {
		t.Fatalf("expected deception-cap gate, got %v", d.Gates)
	}
}

func hasGate(gates []string, name string) bool {
	for _, g := range gates {
		if g == name {
			return true
		}
	}
	return false
}
