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

.PHONY: all test build image clean version deploy exercise teardown
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

# Deploys Vault dev server and a locally built Agent Injector.
# Run multiple times to deploy new builds of the injector.
deploy: image
	kind load docker-image hashicorp/vault-k8s:$(VERSION)
	helm upgrade --install vault vault --repo https://helm.releases.hashicorp.com --version=$(HELM_CHART_VERSION) \
		--wait --timeout=5m \
		--set 'server.dev.enabled=true' \
		--set 'server.logLevel=debug' \
		--set 'injector.image.tag=$(VERSION)' \
		--set 'injector.image.pullPolicy=Never' \
		--set 'injector.affinity=null' \
		--set 'injector.annotations.deployed=unix-$(shell date +%s)'

# Populates the Vault dev server with a secret, configures kubernetes auth, and
# deploys an nginx pod with annotations to have the secret injected.
exercise:
	kubectl exec vault-0 -- vault kv put secret/test-app hello=world
	kubectl exec vault-0 -- vault auth enable jwt || true
	kubectl exec vault-0 -- sh -c 'vault write auth/jwt/config oidc_discovery_url=https://kubernetes.default.svc.cluster.local oidc_discovery_ca_pem=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
	echo 'path "secret/data/*" { capabilities = ["read"] }' | kubectl exec -i vault-0 -- vault policy write test-app -
	kubectl exec vault-0 -- vault write auth/jwt/role/test-app \
		role_type="jwt" \
		bound_audiences="https://kubernetes.default.svc.cluster.local" \
		user_claim="sub" \
		bound_subject="system:serviceaccount:default:test-app-sa" \
		policies="test-app" \
		ttl="1h"
	kubectl create serviceaccount test-app-sa || true
	kubectl delete pod nginx --ignore-not-found
	kubectl run nginx \
		--image=nginx \
		--annotations="vault.hashicorp.com/agent-inject=true" \
		--annotations="vault.hashicorp.com/role=test-app" \
		--annotations="vault.hashicorp.com/auth-type=jwt" \
		--annotations="vault.hashicorp.com/auth-path=auth/jwt" \
		--annotations="vault.hashicorp.com/auth-config-path=/var/run/secrets/kubernetes.io/serviceaccount/token" \
		--annotations="vault.hashicorp.com/auth-config-remove-jwt-after-reading=false" \
		--annotations="vault.hashicorp.com/agent-inject-secret-secret.txt=secret/data/test-app" \
		--overrides='{ "apiVersion": "v1", "spec": { "serviceAccountName": "test-app-sa" } }'
	kubectl wait --for=condition=Ready --timeout=5m pod nginx
	kubectl exec nginx -c nginx -- cat /vault/secrets/secret.txt
	kubectl logs nginx -c vault-agent-init
	kubectl get pod nginx \
		-o jsonpath='{$$.spec.initContainers[?(@.name == "vault-agent-init")].env[?(@.name == "VAULT_CONFIG")].value}' \
		| base64 -d \
		| jq '.auto_auth.method.config.remove_jwt_after_reading'


# Teardown any resources created in deploy and exercise targets.
teardown:
	helm uninstall vault || true
	kubectl delete --ignore-not-found serviceaccount test-app-sa
	kubectl delete --ignore-not-found pod nginx

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
