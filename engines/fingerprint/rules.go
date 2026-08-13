package fingerprint

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed rules.json
var embeddedRules []byte

func DefaultRuleSet() (RuleSet, error) {
	var set RuleSet
	if err := json.Unmarshal(embeddedRules, &set); err != nil {
		return RuleSet{}, fmt.Errorf("fingerprint: parse embedded ruleset: %w", err)
	}
	return set, nil
}

func DefaultEngine() (*Engine, error) {
	set, err := DefaultRuleSet()
	if err != nil {
		return nil, err
	}
	return NewEngine(set)
}
