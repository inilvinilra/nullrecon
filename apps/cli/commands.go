package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/identity"
	"github.com/nullrecon/nullrecon/platform/auditlog"
	"github.com/nullrecon/nullrecon/platform/config"
	"github.com/nullrecon/nullrecon/platform/database"
	"github.com/nullrecon/nullrecon/platform/secretvault"
)

const buildVersion = "0.1.0-dev"

type commandContext struct {
	dataDir string
	jsonOut bool
	stdout  io.Writer
	stderr  io.Writer
	stdin   io.Reader
}

func versionString() string {
	return buildVersion
}

func defaultConfig() (config.Config, error) {
	return config.Default()
}

func (c commandContext) emit(v any) int {
	if c.jsonOut {
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			fmt.Fprintf(c.stderr, "nullrecon: %v\n", err)
			return exitError
		}
		fmt.Fprintln(c.stdout, string(data))
		return exitOK
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(c.stderr, "nullrecon: %v\n", err)
		return exitError
	}
	fmt.Fprintln(c.stdout, string(data))
	return exitOK
}

func (c commandContext) fail(code int, format string, args ...any) int {
	fmt.Fprintf(c.stderr, "nullrecon: "+format+"\n", args...)
	return code
}

func configOf(c commandContext) config.Config {
	return config.ForDataDir(c.dataDir)
}

func (c commandContext) openDB() (*database.DB, error) {
	cfg := config.ForDataDir(c.dataDir)
	db, err := database.Open(cfg.DatabasePath)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func flagValue(args []string, name string) (string, bool) {
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			return args[i+1], true
		}
		if strings.HasPrefix(args[i], name+"=") {
			return strings.TrimPrefix(args[i], name+"="), true
		}
	}
	return "", false
}

func (c commandContext) cmdInit(args []string) int {
	cfg := config.ForDataDir(c.dataDir)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return c.fail(exitError, "%v", err)
	}
	db, err := database.Open(cfg.DatabasePath)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		return c.fail(exitError, "%v", err)
	}
	if _, err := secretvault.Open(cfg.VaultDir); err != nil {
		return c.fail(exitError, "%v", err)
	}
	if err := os.MkdirAll(cfg.EvidenceDir, 0o700); err != nil {
		return c.fail(exitError, "%v", err)
	}
	if err := cfg.Save(); err != nil {
		return c.fail(exitError, "%v", err)
	}
	log := auditlog.New(db)
	if _, err := log.Append(context.Background(), "", "cli", "init", "", "workspace initialized", ""); err != nil {
		return c.fail(exitError, "%v", err)
	}
	return c.emit(map[string]string{"status": "initialized", "dataDir": cfg.DataDir})
}

func (c commandContext) cmdProject(args []string) int {
	if len(args) == 0 {
		return c.fail(exitUsage, "project requires a subcommand")
	}
	switch args[0] {
	case "create":
		name, okName := flagValue(args, "--name")
		slug, okSlug := flagValue(args, "--slug")
		if !okName || !okSlug {
			return c.fail(exitUsage, "project create requires --name and --slug")
		}
		db, err := c.openDB()
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		defer db.Close()
		if existing, err := db.Projects().BySlug(context.Background(), slug); err == nil {
			return c.emit(existing)
		}
		project := identity.NewProject(name, slug)
		if err := db.Projects().Put(context.Background(), project); err != nil {
			return c.fail(exitError, "%v", err)
		}
		log := auditlog.New(db)
		if _, err := log.Append(context.Background(), project.ID, "cli", "project.create", "", "project created", ""); err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(project)
	case "show":
		slug, ok := flagValue(args, "--slug")
		if !ok {
			return c.fail(exitUsage, "project show requires --slug")
		}
		db, err := c.openDB()
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		defer db.Close()
		project, err := db.Projects().BySlug(context.Background(), slug)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(project)
	case "authorize":
		return c.projectAuthorize(args)
	}
	return c.fail(exitUsage, "unknown project subcommand %q", args[0])
}

func (c commandContext) projectAuthorize(args []string) int {
	slug, ok := flagValue(args, "--project")
	if !ok {
		return c.fail(exitUsage, "project authorize requires --project")
	}
	modesRaw, ok := flagValue(args, "--modes")
	if !ok {
		return c.fail(exitUsage, "project authorize requires --modes (comma-separated)")
	}
	var modes []string
	for _, m := range strings.Split(modesRaw, ",") {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if _, err := policy.ParseMode(m); err != nil {
			return c.fail(exitUsage, "unknown mode %q", m)
		}
		modes = append(modes, m)
	}
	if len(modes) == 0 {
		return c.fail(exitUsage, "project authorize requires at least one mode")
	}
	source, ok := flagValue(args, "--source")
	if !ok {
		source = "cli"
	}
	reference, _ := flagValue(args, "--reference")
	days := 30
	if raw, ok := flagValue(args, "--days"); ok {
		n, err := parsePositiveInt(raw)
		if err != nil {
			return c.fail(exitUsage, "--days must be a positive integer")
		}
		days = n
	}
	db, err := c.openDB()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	defer db.Close()
	ctx := context.Background()
	project, err := db.Projects().BySlug(ctx, slug)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	now := time.Now().UTC()
	authz := identity.NewAuthorization(project.ID, source, reference, modes, now, now.AddDate(0, 0, days))
	if err := db.Authorizations().Put(ctx, authz); err != nil {
		return c.fail(exitError, "%v", err)
	}
	log := auditlog.New(db)
	if _, err := log.Append(ctx, project.ID, "cli", "project.authorize", authz.ID, "authorization granted", strings.Join(modes, ",")); err != nil {
		return c.fail(exitError, "%v", err)
	}
	return c.emit(authz)
}

func parsePositiveInt(raw string) (int, error) {
	n := 0
	if raw == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(r-'0')
	}
	if n <= 0 {
		return 0, fmt.Errorf("not positive")
	}
	return n, nil
}

func (c commandContext) cmdScope(args []string) int {
	if len(args) == 0 {
		return c.fail(exitUsage, "scope requires a subcommand")
	}
	switch args[0] {
	case "import":
		return c.scopeImport(args[1:])
	case "validate":
		file, ok := flagValue(args, "--file")
		if !ok {
			return c.fail(exitUsage, "scope validate requires --file")
		}
		scope, err := loadScopeFile(file)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(map[string]string{"status": "valid", "version": scope.Version})
	case "explain":
		return c.scopeExplain(args[1:])
	}
	return c.fail(exitUsage, "unknown scope subcommand %q", args[0])
}

func loadScopeFile(path string) (scopeguard.Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return scopeguard.Scope{}, err
	}
	var scope scopeguard.Scope
	if err := json.Unmarshal(data, &scope); err != nil {
		return scopeguard.Scope{}, err
	}
	if err := scope.Normalize(); err != nil {
		return scopeguard.Scope{}, err
	}
	return scope, nil
}

func (c commandContext) scopeImport(args []string) int {
	slug, okSlug := flagValue(args, "--project")
	label, okLabel := flagValue(args, "--label")
	file, okFile := flagValue(args, "--file")
	if !okSlug || !okLabel || !okFile {
		return c.fail(exitUsage, "scope import requires --project, --label and --file")
	}
	scope, err := loadScopeFile(file)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	db, err := c.openDB()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	defer db.Close()
	project, err := db.Projects().BySlug(context.Background(), slug)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	id, err := db.Scopes().Put(context.Background(), project.ID, label, scope)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	log := auditlog.New(db)
	if _, err := log.Append(context.Background(), project.ID, "cli", "scope.import", "", "scope imported", label); err != nil {
		return c.fail(exitError, "%v", err)
	}
	return c.emit(map[string]string{"status": "imported", "scopeId": id})
}

func (c commandContext) scopeExplain(args []string) int {
	slug, okSlug := flagValue(args, "--project")
	label, okLabel := flagValue(args, "--label")
	modeRaw, okMode := flagValue(args, "--mode")
	if !okSlug || !okLabel || !okMode {
		return c.fail(exitUsage, "scope explain requires --project, --label and --mode")
	}
	mode, err := policy.ParseMode(modeRaw)
	if err != nil {
		return c.fail(exitUsage, "%v", err)
	}
	target := scopeguard.Target{}
	if v, ok := flagValue(args, "--host"); ok {
		target.Host = v
	}
	if v, ok := flagValue(args, "--ip"); ok {
		target.IP = v
	}
	if v, ok := flagValue(args, "--protocol"); ok {
		target.Protocol = v
	}
	if v, ok := flagValue(args, "--path"); ok {
		target.Path = v
	}
	if v, ok := flagValue(args, "--port"); ok {
		var port int
		if _, err := fmt.Sscanf(v, "%d", &port); err != nil {
			return c.fail(exitUsage, "invalid port %q", v)
		}
		target.Port = port
	}
	db, err := c.openDB()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	defer db.Close()
	project, err := db.Projects().BySlug(context.Background(), slug)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	scope, err := db.Scopes().Get(context.Background(), project.ID, label)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	authzs, err := db.Authorizations().ForProject(context.Background(), project.ID)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	now := time.Now().UTC()
	var authz *identity.Authorization
	for i := range authzs {
		a := authzs[i]
		if !a.ValidAt(now) {
			continue
		}
		for _, m := range a.AllowedModes {
			if m == string(mode) {
				copy := a
				authz = &copy
			}
		}
	}
	if authz == nil {
		return c.emit(scopeguard.Decision{Allowed: false, Class: "unknown", Reasons: []string{"no valid authorization covers this mode at the current time"}})
	}
	snap, err := scopeguard.Compile(project, *authz, scope, mode, now)
	if err != nil {
		return c.emit(scopeguard.Decision{Allowed: false, Class: "unknown", Reasons: []string{err.Error()}})
	}
	decision := snap.Evaluate(target, now)
	return c.emit(decision)
}
