.PHONY:	all build

# Default target
all: build

build:
	docker build -t hashicorp/webhook-build:build -f ./build/docker/Dockerfile.build .
	docker create --name extract hashicorp/webhook-build:build
	docker cp extract:/go/src/github.com/hashicorp/webhook/webhook ./bin/webhook
	docker rm -f extract
	docker build -t webhook -f ./build/docker/Dockerfile .
	docker tag webhook hashicorp/webhook:0.0.1
