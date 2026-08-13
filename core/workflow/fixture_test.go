package workflow

import (
	"testing"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func scopeFixture(t *testing.T) (identity.Project, identity.Authorization, scopeguard.Scope) {
	t.Helper()
	now := time.Now().UTC()
	project := identity.NewProject("T", "t")
	authz := identity.NewAuthorization(project.ID, "src", "", []string{"passive", "safeactive", "authorizedtest"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	scope := scopeguard.NewScope()
	scope.RootDomains = []string{"example.com"}
	return project, authz, scope
}

func compileSnapshot(project identity.Project, authz identity.Authorization, scope scopeguard.Scope, mode policy.Mode) (scopeguard.Snapshot, error) {
	return scopeguard.Compile(project, authz, scope, mode, time.Now().UTC())
}
