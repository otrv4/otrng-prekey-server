GIT_VERSION=$(shell git rev-parse HEAD)
TAG_VERSION=$(shell git tag -l --contains $$GIT_VERSION | tail -1)

# BUILD_DIR=bin

GOLIST=go list ./...

default: test

test:
	go test -cover -v ./...

build:
	go build -i

.PHONY: build test

deps:
	go get -u github.com/golang/lint/golint
    #dep should also be installed, but globally.
#	go get -u github.com/kardianos/govendor
#	go get -u github.com/modocache/gover
#	go get -u github.com/rosatolen/esc

lint:
	for pkg in $$($(GOLIST) ./...) ; do \
		golint $$pkg ; \
	done
