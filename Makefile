GIT_VERSION=$(shell git rev-parse HEAD)
TAG_VERSION=$(shell git tag -l --contains $$GIT_VERSION | tail -1)

BUILD_DIR=bin

GOTEST=govendor test +local

default: test

test:
	$(GOTEST) -cover -v ./...
.PHONY: test

build:
	go build -i -o $(BUILD_DIR)/otrng-prekey-server
