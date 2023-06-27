REGISTRY_NAME?=docker.io/hashicorp
IMAGE_NAME=vault-k8s
VERSION?=0.0.0-dev
IMAGE_TAG?=$(REGISTRY_NAME)/$(IMAGE_NAME):$(VERSION)
PUBLISH_LOCATION?=https://releases.hashicorp.com
DOCKER_DIR=./build/docker
BUILD_DIR=dist
GOOS?=linux
GOARCH?=amd64
BIN_NAME=$(IMAGE_NAME)
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)
XC_PUBLISH?=
PKG=github.com/hashicorp/vault-k8s/version
LDFLAGS?="-X '$(PKG).Version=v$(VERSION)'"
TESTARGS ?= '-test.v'

HELM_CHART_VERSION ?= 0.25.0

.PHONY: all test build image clean version deploy
all: build

version:
	@echo $(VERSION)

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-ldflags $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BIN_NAME) \
		.

image: build
	docker build --build-arg VERSION=$(VERSION) --no-cache -t $(IMAGE_TAG) .

deploy:
	kind load docker-image hashicorp/vault-k8s:$(VERSION)
	helm upgrade --install vault vault --repo https://helm.releases.hashicorp.com --version=$(HELM_CHART_VERSION) \
		--wait --timeout=5m \
		--set 'server.dev.enabled=true' \
		--set 'injector.image.tag=$(VERSION)' \
		--set 'injector.image.pullPolicy=Never' \
		--set 'injector.affinity=null' \
		--set 'injector.annotations.deployed=unix-$(shell date +%s)'

clean:
	-rm -rf $(BUILD_DIR)

test: unit-test

unit-test:
	go test -race $(TESTARGS) ./...

.PHONY: mod
mod:
	@go mod tidy

fmt:
	gofmt -w $(GOFMT_FILES)
