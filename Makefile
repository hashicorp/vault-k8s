REGISTRY_NAME?=docker.io/hashicorp
IMAGE_NAME=vault-k8s
VERSION?=$(shell git tag | tail -1)
IMAGE_TAG=$(REGISTRY_NAME)/$(IMAGE_NAME):$(VERSION)
IMAGE_TAG_LATEST=$(REGISTRY_NAME)/$(IMAGE_NAME):latest
BUILD_DIR=.build
GOOS?=linux
GOARCH?=amd64

.PHONY: all build image clean test-style
all: build

test: test-style
	go test github.com/deislabs/secrets-store-csi-driver/pkg/... -cover
	go vet github.com/deislabs/secrets-store-csi-driver/pkg/...

test-style: setup
	@echo "==> Running static validations and linters <=="
	golangci-lint run

sanity-test:
	go test -v ./test/sanity

build:
	CGO_ENABLED=0 go build -a -o $(BUILD_DIR)/vault-k8s_$(GOOS)_$(GOARCH)_$(VERSION) main.go

image: build 
	docker build --build-arg VERSION=$(VERSION) --no-cache -t $(IMAGE_TAG) .

docker-login:
	echo $(DOCKER_PASSWORD) | docker login -u $(DOCKER_USERNAME) --password-stdin

deploy: image docker-login
	docker push $(IMAGE_TAG)
	docker tag $(IMAGE_TAG) $(IMAGE_TAG_LATEST)
	docker push $(IMAGE_TAG_LATEST)

clean:
	-rm -rf $(BUILD_DIR) 

.PHONY: mod
mod:
	@go mod tidy
