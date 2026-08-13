package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/engines/cvefeed"
	"github.com/nullrecon/nullrecon/platform/database"
	"github.com/nullrecon/nullrecon/providers/nvd"
	"github.com/ulikunitz/xz"
)

const feedURLBase = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-"

func (c commandContext) cveImport(db *database.DB, args []string) int {
	ctx := context.Background()
	ingestor := cvefeed.NewIngestor()
	stored := 0

	ingest := func(label string, data []byte) error {
		records, err := nvd.ParseFeed(data)
		if err != nil {
			return err
		}
		merged := ingestor.Merge(records)
		for _, rec := range merged {
			if err := db.CVEKnowledge().Upsert(ctx, rec); err != nil {
				return err
			}
			stored++
		}
		fmt.Fprintf(c.stderr, "cve import: %s -> %d records, %d stored total\n", label, len(records), stored)
		return nil
	}

	if flagPresent(args, "--feed") {
		from := yearFlag(args, "--from", 1999)
		to := yearFlag(args, "--to", time.Now().UTC().Year())
		client := &http.Client{Timeout: 180 * time.Second}
		var failures []string
		for year := from; year <= to; year++ {
			data, err := fetchFeedYear(ctx, client, year)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%d: %v", year, err))
				continue
			}
			if err := ingest(strconv.Itoa(year), data); err != nil {
				failures = append(failures, fmt.Sprintf("%d: %v", year, err))
			}
		}
		return c.emit(map[string]any{"stored": stored, "from": from, "to": to, "failures": failures})
	}

	var paths []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			paths = append(paths, a)
		}
	}
	if len(paths) == 0 {
		return c.fail(exitUsage, "cve import requires a file/directory path or --feed")
	}
	for _, p := range paths {
		data, err := readMaybeXZ(p)
		if err != nil {
			return c.fail(exitError, "%v", err)
		}
		if err := ingest(p, data); err != nil {
			return c.fail(exitError, "%v", err)
		}
	}
	return c.emit(map[string]any{"stored": stored})
}

func fetchFeedYear(ctx context.Context, client *http.Client, year int) ([]byte, error) {
	url := feedURLBase + strconv.Itoa(year) + ".json.xz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	reader, err := xz.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}

func readMaybeXZ(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if strings.HasSuffix(path, ".xz") {
		reader, err := xz.NewReader(f)
		if err != nil {
			return nil, err
		}
		return io.ReadAll(reader)
	}
	return io.ReadAll(f)
}

func yearFlag(args []string, flag string, fallback int) int {
	if raw, ok := flagValue(args, flag); ok {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1999 && n <= 2100 {
			return n
		}
	}
	return fallback
}
