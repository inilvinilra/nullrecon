package scopeguard

import (
	"fmt"
	"time"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/domain/identity"
)

type Snapshot struct {
	contracts.Versioned
	ID              string      `json:"id"`
	ProjectID       string      `json:"projectId"`
	AuthorizationID string      `json:"authorizationId"`
	Mode            policy.Mode `json:"mode"`
	Scope           Scope       `json:"scope"`
	CompiledAt      time.Time   `json:"compiledAt"`
	Hash            string      `json:"hash"`
}

func Compile(project identity.Project, authz identity.Authorization, scope Scope, mode policy.Mode, now time.Time) (Snapshot, error) {
	now = now.UTC()
	if project.ID == "" || authz.ID == "" {
		return Snapshot{}, fmt.Errorf("scopeguard: project and authorization are required")
	}
	if project.Status != identity.ProjectActive {
		return Snapshot{}, fmt.Errorf("scopeguard: project %s is not active", project.ID)
	}
	if authz.ProjectID != project.ID {
		return Snapshot{}, fmt.Errorf("scopeguard: authorization does not belong to project")
	}
	if !authz.ValidAt(now) {
		return Snapshot{}, fmt.Errorf("scopeguard: authorization is not valid at %s", now.Format(time.RFC3339))
	}
	if !mode.Valid() {
		return Snapshot{}, fmt.Errorf("scopeguard: invalid mode %q", mode)
	}
	granted := false
	for _, m := range authz.AllowedModes {
		if m == string(mode) {
			granted = true
			break
		}
	}
	if !granted {
		return Snapshot{}, fmt.Errorf("scopeguard: mode %s is not covered by the authorization", mode)
	}
	normalized := scope
	if err := normalized.Normalize(); err != nil {
		return Snapshot{}, err
	}
	snap := Snapshot{
		Versioned:       contracts.NewVersioned("scopesnapshot"),
		ID:              contracts.NewID("scp"),
		ProjectID:       project.ID,
		AuthorizationID: authz.ID,
		Mode:            mode,
		Scope:           normalized,
		CompiledAt:      now,
	}
	hash, err := snap.computeHash()
	if err != nil {
		return Snapshot{}, err
	}
	snap.Hash = hash
	return snap, nil
}

func (s Snapshot) computeHash() (string, error) {
	c := s
	c.ID = ""
	c.CompiledAt = time.Time{}
	c.Hash = ""
	return contracts.HashHex(c)
}

func (s Snapshot) ValidAt(t time.Time) bool {
	return withinWindows(s.Scope.TimeWindows, t.UTC())
}

func withinWindows(windows []TimeWindow, t time.Time) bool {
	if len(windows) == 0 {
		return true
	}
	clock := t.Format("15:04")
	for _, w := range windows {
		if w.StartUTC <= w.EndUTC {
			if clock >= w.StartUTC && clock <= w.EndUTC {
				return true
			}
			continue
		}
		if clock >= w.StartUTC || clock <= w.EndUTC {
			return true
		}
	}
	return false
}
