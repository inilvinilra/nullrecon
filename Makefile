GO ?= go
BIN := bin/nullrecon

.PHONY: all build test vet fmt check ci clean

all: check build

build:
	$(GO) build -o $(BIN) ./apps/cli

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

check:
	$(GO) run ./deploy/checks -root .

ci: check vet test build

clean:
	rm -rf bin coverage.out
