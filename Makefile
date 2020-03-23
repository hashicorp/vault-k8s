IMAGE_NAME=vault-k8s
VERSION?=0.3.0
IMAGE_TAG=$(REGISTRY_NAME)/$(IMAGE_NAME):$(VERSION)
DOCKER_DIR=./build/docker
BUILD_DIR=.build
GOOS?=linux
GOARCH?=amd64
BIN_NAME=$(IMAGE_NAME)_$(GOOS)_$(GOARCH)_$(VERSION)

.PHONY: all test build image clean 
all: build

build:
	GO111MODULE=on CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -a -o $(BUILD_DIR)/$(BIN_NAME) .

image: build
	docker build --build-arg NAME=$(IMAGE_NAME) --build-arg VERSION=$(VERSION) --no-cache -t $(IMAGE_TAG) -f $(DOCKER_DIR)/Dockerfile.dev .

clean:
	-rm -rf $(BUILD_DIR)

test: unit-test

unit-test:
	go test -race ./...

.PHONY: mod
mod:
	@go mod tidy
