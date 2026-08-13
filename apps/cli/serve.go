package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/nullrecon/nullrecon/httpapi"
)

func (c commandContext) cmdServe(args []string) int {
	addr, ok := flagValue(args, "--addr")
	if !ok {
		addr = "127.0.0.1:8787"
	}
	db, err := c.openDB()
	if err != nil {
		return c.fail(exitError, "%v", err)
	}
	defer db.Close()

	server := httpapi.NewServer(db, buildRegistry())
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	fmt.Fprintf(c.stderr, "nullrecon api listening on http://%s (Ctrl+C to stop)\n", addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return c.fail(exitError, "%v", err)
	}
	return exitOK
}
