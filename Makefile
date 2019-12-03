GIT_VERSION=$(shell git rev-parse HEAD)
TAG_VERSION=$(shell git tag -l --contains $$GIT_VERSION | tail -1)

BUILD_DIR=bin

GOLIST=go list ./...

default: test

test:
	go test -cover -v ./...

build:
	go build -i

raw:
	mkdir -p $(BUILD_DIR)
	go build -i -o $(BUILD_DIR)/raw-server ./server/raw

http:
	mkdir -p $(BUILD_DIR)
	go build -i -o $(BUILD_DIR)/http-server ./server/http

all: build raw http

.PHONY: build test

deps:
	go get -u golang.org/x/lint/golint
    #dep should also be installed, but globally.

lint:
	for pkg in $$($(GOLIST) ./...) ; do \
		golint $$pkg ; \
	done

cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out

ineffassign:
	go get -u github.com/gordonklaus/ineffassign/...
	ineffassign .
