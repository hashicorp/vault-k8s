.PHONY:	all build

IMAGE_NAME=hashicorp/vault-k8s
IMAGE_VERSION=0.1.0

# Default target
all: build

test:
	go test -v ./... -race

build:
	GOOS=linux GOARCH=amd64 go build -o ./bin/vault-k8s .
	docker build -t vault-k8s -f ./docker/Dockerfile .
	docker tag vault-k8s $(IMAGE_NAME):$(IMAGE_VERSION)
