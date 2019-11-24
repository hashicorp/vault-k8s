.PHONY:	all build

# Default target
all: build

build:
	GOOS=linux GOARCH=amd64 go build -o ./bin/vault-k8s .
	docker build -t vault-k8s -f ./docker/Dockerfile .
	docker tag vault-k8s hashicorp/vault-k8s:0.0.1
