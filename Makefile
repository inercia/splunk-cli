GO ?= go
BINARY_NAME := splunk-cli
CMD_DIR := ./cmd/splunk-cli
BIN_DIR := ./bin

.PHONY: all build test fmt lint tidy clean run

all: build

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_DIR)

test:
	$(GO) test ./...

fmt:
	$(GO) fmt ./...
	gofmt -s -w .

lint:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN_DIR)

run: build
	$(BIN_DIR)/$(BINARY_NAME)
