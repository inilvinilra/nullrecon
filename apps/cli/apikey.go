package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/nullrecon/nullrecon/contracts"
	"github.com/nullrecon/nullrecon/domain/identity"
)

func (c commandContext) cmdAPIKey(args []string) int {
	if len(args) == 0 {
		return c.fail(exitUsage, "apikey requires a subcommand (create, list, revoke)")
	}
	db, err := c.openDB()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	defer db.Close()
	ctx := context.Background()
	switch args[0] {
	case "create":
		name, ok := flagValue(args, "--name")
		if !ok {
			return c.fail(exitUsage, "apikey create requires --name")
		}
		roleStr, ok := flagValue(args, "--role")
		if !ok {
			roleStr = string(identity.RoleViewer)
		}
		role := identity.Role(roleStr)
		if !role.Valid() {
			return c.fail(exitUsage, "invalid role %q (viewer, operator, admin)", roleStr)
		}
		secret, err := generateKey()
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		key := identity.APIKey{
			ID:        contracts.NewID("key"),
			Name:      name,
			KeyHash:   hashKey(secret),
			Role:      role,
			CreatedAt: time.Now().UTC(),
		}
		if err := db.APIKeys().Put(ctx, key); err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(map[string]any{"id": key.ID, "name": key.Name, "role": key.Role, "key": secret, "note": "store this key now; it is not recoverable"})
	case "list":
		keys, err := db.APIKeys().List(ctx)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(map[string]any{"apiKeys": keys, "count": len(keys)})
	case "revoke":
		id, ok := positionalOrFlag(args[1:], "--id")
		if !ok {
			return c.fail(exitUsage, "apikey revoke requires an id")
		}
		if err := db.APIKeys().Revoke(ctx, id); err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(map[string]string{"status": "revoked", "id": id})
	}
	return c.fail(exitUsage, "unknown apikey subcommand %q", args[0])
}

func generateKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "nrk_" + hex.EncodeToString(buf), nil
}

func hashKey(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
