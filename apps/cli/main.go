package main

import (
	"fmt"
	"io"
	"os"
)

const (
	exitOK     = 0
	exitError  = 1
	exitUsage  = 2
	exitPolicy = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	dataDir := ""
	jsonOut := false
	var rest []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--data-dir":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "nullrecon: --data-dir requires a value")
				return exitUsage
			}
			dataDir = args[i+1]
			i++
		case "--json":
			jsonOut = true
		default:
			rest = append(rest, args[i])
		}
	}
	if dataDir == "" {
		cfg, err := defaultConfig()
		if err != nil {
			fmt.Fprintf(stderr, "nullrecon: %v\n", err)
			return exitError
		}
		dataDir = cfg.DataDir
	}
	if len(rest) == 0 {
		printUsage(stdout)
		return exitUsage
	}
	ctx := commandContext{dataDir: dataDir, jsonOut: jsonOut, stdout: stdout, stderr: stderr, stdin: os.Stdin}
	switch rest[0] {
	case "init":
		return ctx.cmdInit(rest[1:])
	case "project":
		return ctx.cmdProject(rest[1:])
	case "scope":
		return ctx.cmdScope(rest[1:])
	case "provider":
		return ctx.cmdProvider(rest[1:])
	case "service":
		return ctx.cmdService(rest[1:])
	case "asset":
		return ctx.cmdAsset(rest[1:])
	case "workflow":
		return ctx.cmdWorkflow(rest[1:])
	case "scan":
		return ctx.cmdScan(rest[1:])
	case "origin":
		return ctx.cmdOrigin(rest[1:])
	case "subdomain":
		return ctx.cmdSubdomain(rest[1:])
	case "exposure":
		return ctx.cmdExposure(rest[1:])
	case "finding":
		return ctx.cmdFinding(rest[1:])
	case "vuln":
		return ctx.cmdVuln(rest[1:])
	case "cve":
		return ctx.cmdCVE(rest[1:])
	case "template":
		return ctx.cmdTemplate(rest[1:])
	case "apikey":
		return ctx.cmdAPIKey(rest[1:])
	case "serve":
		return ctx.cmdServe(rest[1:])
	case "report":
		return ctx.cmdReport(rest[1:])
	case "version":
		return ctx.emit(map[string]string{"version": versionString()})
	}
	fmt.Fprintf(stderr, "nullrecon: unknown command %q\n", rest[0])
	printUsage(stderr)
	return exitUsage
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `nullrecon - reconnaissance and evidence platform

usage: nullrecon [--data-dir DIR] [--json] COMMAND ...

commands:
  init
  project create --name NAME --slug SLUG
  project show --slug SLUG
  project authorize --project SLUG --modes MODE[,MODE] [--source S] [--reference R] [--days N]
  scope import --project SLUG --label LABEL --file SCOPE.json
  scope validate --file SCOPE.json
  scope explain --project SLUG --label LABEL --mode MODE [--host HOST] [--ip IP] [--port N] [--protocol P] [--path PATH]
  provider list
  provider configure NAME
  provider health
  provider usage
  service list [--category CAT]
  workflow plan NAME --project SLUG --label LABEL --mode MODE
  workflow run NAME --project SLUG --label LABEL --mode MODE
  scan status --run RUNID
  scan cancel --run RUNID
  origin --domain DOMAIN --project SLUG --label LABEL --mode MODE [--host SUB] [--ip IP]
  exposure --project SLUG --label LABEL --mode MODE (--url URL | --domain DOMAIN) ...
  finding list --project SLUG
  finding show FINDINGID
  vuln list --project SLUG
  cve sync (--kev | --cve CVE | --keyword KW | --since DATE [--until DATE])
  cve stats
  cve show CVE
  template list
  report build --project SLUG [--format json|markdown|sarif] [--out FILE] [--run RUNID]
  apikey create --name NAME [--role viewer|operator|admin]
  apikey list
  apikey revoke ID
  serve [--addr HOST:PORT]
  version`)
}
