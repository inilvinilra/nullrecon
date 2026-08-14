package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nullrecon/nullrecon/platform/database"
	"github.com/nullrecon/nullrecon/platform/secretvault"
	"github.com/nullrecon/nullrecon/providers/censys"
	"github.com/nullrecon/nullrecon/providers/certspotter"
	"github.com/nullrecon/nullrecon/providers/cisa"
	"github.com/nullrecon/nullrecon/providers/crtsh"
	"github.com/nullrecon/nullrecon/providers/epss"
	"github.com/nullrecon/nullrecon/providers/fofa"
	"github.com/nullrecon/nullrecon/providers/hackertarget"
	"github.com/nullrecon/nullrecon/providers/leakix"
	"github.com/nullrecon/nullrecon/providers/netlas"
	"github.com/nullrecon/nullrecon/providers/nvd"
	"github.com/nullrecon/nullrecon/providers/rapiddns"
	"github.com/nullrecon/nullrecon/providers/registry"
	"github.com/nullrecon/nullrecon/providers/shodan"
	"github.com/nullrecon/nullrecon/providers/urlscan"
	"github.com/nullrecon/nullrecon/providers/virustotal"
	"github.com/nullrecon/nullrecon/providers/zoomeye"
)

func buildRegistry() *registry.Registry {
	reg := registry.New()
	for _, a := range []registry.Adapter{
		fofa.New(envOr("NULLRECON_FOFA_ENDPOINT", "")),
		censys.New(envOr("NULLRECON_CENSYS_ENDPOINT", "")),
		netlas.New(envOr("NULLRECON_NETLAS_ENDPOINT", "")),
		shodan.New(envOr("NULLRECON_SHODAN_ENDPOINT", "")),
		leakix.New(envOr("NULLRECON_LEAKIX_ENDPOINT", "")),
		nvd.New(envOr("NULLRECON_NVD_ENDPOINT", "")),
		epss.New(envOr("NULLRECON_EPSS_ENDPOINT", "")),
		cisa.New(envOr("NULLRECON_CISA_ENDPOINT", "")),
		crtsh.New(envOr("NULLRECON_CRTSH_ENDPOINT", "")),
		certspotter.New(envOr("NULLRECON_CERTSPOTTER_ENDPOINT", "")),
		rapiddns.New(envOr("NULLRECON_RAPIDDNS_ENDPOINT", "")),
		hackertarget.New(envOr("NULLRECON_HACKERTARGET_ENDPOINT", "")),
		urlscan.New(envOr("NULLRECON_URLSCAN_ENDPOINT", "")),
		virustotal.New(envOr("NULLRECON_VIRUSTOTAL_ENDPOINT", "")),
		zoomeye.New(envOr("NULLRECON_ZOOMEYE_ENDPOINT", "")),
	} {
		reg.Register(a)
	}
	return reg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type vaultResolver struct {
	db    *database.DB
	vault *secretvault.Vault
}

func (r vaultResolver) Resolve(secretRef string) (string, error) {
	name := strings.TrimPrefix(secretRef, "provider/")
	cfg, err := r.db.ProviderConfigs().Get(context.Background(), name)
	if err != nil {
		return "", err
	}
	if cfg.SecretRef == "" {
		return "", fmt.Errorf("no credential stored for provider %s", name)
	}
	secret, err := r.vault.OpenSecret(cfg.SecretRef)
	if err != nil {
		return "", err
	}
	return string(secret), nil
}

func (c commandContext) cmdProvider(args []string) int {
	if len(args) == 0 {
		return c.fail(exitUsage, "provider requires a subcommand")
	}
	reg := buildRegistry()
	switch args[0] {
	case "list":
		return c.emit(reg.Descriptors())
	case "configure":
		if len(args) < 2 {
			return c.fail(exitUsage, "provider configure requires a provider name")
		}
		return c.providerConfigure(reg, args[1])
	case "health":
		db, err := c.openDB()
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		defer db.Close()
		vault, err := secretvault.Open(configOf(c).VaultDir)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		exec := registry.NewExecutor(reg, vaultResolver{db: db, vault: vault}, nil)
		type health struct {
			Name       string `json:"name"`
			Healthy    bool   `json:"healthy"`
			Configured bool   `json:"configured"`
		}
		var out []health
		for _, d := range reg.Descriptors() {
			_, err := db.ProviderConfigs().Get(context.Background(), d.Name)
			out = append(out, health{Name: d.Name, Healthy: exec.Healthy(d.Name), Configured: err == nil})
		}
		return c.emit(out)
	case "usage":
		db, err := c.openDB()
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		defer db.Close()
		summary, err := db.Usage().Summary(context.Background())
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		return c.emit(summary)
	}
	return c.fail(exitUsage, "unknown provider subcommand %q", args[0])
}

func (c commandContext) providerConfigure(reg *registry.Registry, name string) int {
	adapter, ok := reg.Get(name)
	if !ok {
		return c.fail(exitUsage, "unknown provider %q", name)
	}
	d := adapter.Describe()
	db, err := c.openDB()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	defer db.Close()
	vault, err := secretvault.Open(configOf(c).VaultDir)
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	secretRef := ""
	if d.Auth.Required {
		fmt.Fprintf(c.stderr, "enter credential for %s (input hidden from logs, stored encrypted): ", name)
		secret, err := readSecret(c)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		if secret == "" {
			return c.fail(exitUsage, "empty credential rejected")
		}
		ref, err := vault.Seal("providers", []byte(secret))
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		secretRef = ref
	}
	if err := db.ProviderConfigs().Put(context.Background(), name, d.AdapterVersion, true, secretRef); err != nil {
		return c.fail(exitError, "%v", err)
	}
	return c.emit(map[string]string{"status": "configured", "provider": name})
}

func readSecret(c commandContext) (string, error) {
	data, err := io.ReadAll(c.stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
