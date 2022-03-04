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

.PHONY: all test build image clean version
all: build

version:
	@echo $(VERSION)

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-a \
		-ldflags $(LDFLAGS) \
		-o $(BUILD_DIR)/$(BIN_NAME) \
		.

image: build
	docker build --build-arg VERSION=$(VERSION) --no-cache -t $(IMAGE_TAG) .

#This target is used as part of the release pipeline in CircleCI, but can also be used to build the production image locally.
#The released/signed linux binary will be pulled from releases.hashicorp.com instead of a local build of the binary.
prod-image:
	docker build -t $(IMAGE_TAG) \
	--build-arg VERSION=$(VERSION) \
	--build-arg LOCATION=$(PUBLISH_LOCATION) \
	-f $(DOCKER_DIR)/Release.dockerfile .

prod-ubi-image:
	docker build -t $(IMAGE_TAG)_ubi \
    --build-arg VERSION=$(VERSION) \
    --build-arg LOCATION=$(PUBLISH_LOCATION) \
    -f $(DOCKER_DIR)/Release.ubi.dockerfile .

# This target is used in CI to cross compile vault-k8s for 4 different architectures
# and publish (when XC_PUBLISH="--push") using docker buildx
xc-prod-image:
	docker buildx build --platform linux/amd64,linux/arm64,linux/386,linux/arm/v6 \
	--build-arg VERSION=$(VERSION) \
	--build-arg LOCATION=$(PUBLISH_LOCATION) \
	$(XC_PUBLISH) \
	-t $(IMAGE_TAG) \
	-f ${DOCKER_DIR}/Release.dockerfile .

clean:
	-rm -rf $(BUILD_DIR)

test: unit-test

unit-test:
	go test -race ./...

.PHONY: mod
mod:
	@go mod tidy

fmt:
	gofmt -w $(GOFMT_FILES)
