BINARY_NAME=phalanx
VERSION=1.0.0
BUILD_DIR=build

.PHONY: all build clean test lint

all: clean test build

build:
	@echo "Building Phalanx $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/phalanx
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/phalanx
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/phalanx
	@echo "Build complete."

test:
	@echo "Running unit tests against malware fixtures..."
	go test -v ./...

clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)
	@rm -rf coverage.out

lint:
	golangci-lint run
