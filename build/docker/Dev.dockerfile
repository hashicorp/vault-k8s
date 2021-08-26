FROM docker.mirror.hashicorp.services/alpine:latest

ARG VERSION=0.10.2

RUN addgroup vault && \
    adduser -S -G vault vault

ADD .build/vault-k8s_linux_amd64_$VERSION /vault-k8s

USER vault

ENTRYPOINT ["/vault-k8s"]
