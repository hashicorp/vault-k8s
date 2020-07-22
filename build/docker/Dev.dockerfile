FROM alpine:latest

ARG VERSION=0.3.0

RUN addgroup vault && \
    adduser -S -G vault vault

ADD .build/vault-k8s_linux_amd64_$VERSION /vault-k8s

USER vault

ENTRYPOINT ["/vault-k8s"]
