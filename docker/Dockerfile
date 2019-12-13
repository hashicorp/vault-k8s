FROM alpine:latest

ARG VERSION=0.1.0

ADD .build/vault-k8s_linux_amd64_$VERSION /vault-k8s

ENTRYPOINT ["/vault-k8s"]
