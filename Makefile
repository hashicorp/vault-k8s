REGISTRY_NAME?=docker.io/hashicorp
IMAGE_NAME=vault-k8s
VERSION?=0.4.0
IMAGE_TAG=$(REGISTRY_NAME)/$(IMAGE_NAME):$(VERSION)
PUBLISH_LOCATION?=https://releases.hashicorp.com
DOCKER_DIR=./build/docker
BUILD_DIR=.build
GOOS?=linux
GOARCH?=amd64
BIN_NAME=$(IMAGE_NAME)_$(GOOS)_$(GOARCH)_$(VERSION)
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)

.PHONY: all test build image clean 
all: build

build:
	GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -a -o $(BUILD_DIR)/$(BIN_NAME) .

image: build
	docker build --build-arg VERSION=$(VERSION) --no-cache -t $(IMAGE_TAG) -f $(DOCKER_DIR)/Dev.dockerfile .

#This target is used as part of the release pipeline in CircleCI, but can also be used to build the production image locally.
#The released/signed linux binary will be pulled from releases.hashicorp.com instead of a local build of the binary.
prod-image:
	docker build -t $(REGISTRY_NAME)/$(IMAGE_NAME):$(VERSION) \
	--build-arg VERSION=$(VERSION) \
	--build-arg LOCATION=$(PUBLISH_LOCATION) \
	-f $(DOCKER_DIR)/Release.dockerfile .

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
