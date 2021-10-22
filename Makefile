GO ?= go

.PHONY: all
all: loader converter

.PHONY: loader
loader:
	$(GO) build $(GOFLAGS) -o $@ ./bin/$@

.PHONY: converter
converter:
	$(GO) build $(GOFLAGS) -o $@ ./bin/$@

.PHONY: update
update:
	$(GO) get -u ./bin/...
	$(GO) mod tidy

