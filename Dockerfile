# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# This Dockerfile contains multiple targets.
# Use 'docker build --target=<name> .' to build one.
# e.g. `docker build --target=dev .`
#
# All non-dev targets have a VERSION argument that must be provided 
# via --build-arg=VERSION=<version> when building. 
# e.g. --build-arg VERSION=1.11.2
#
# `default` is the production docker image which cannot be built locally. 
# For local dev and testing purposes, please build and use the `dev` docker image.

FROM docker.mirror.hashicorp.services/alpine:3.20.1 as dev

RUN addgroup vault && \
    adduser -S -G vault vault

ADD dist/vault-k8s /vault-k8s

USER vault

ENTRYPOINT ["/vault-k8s"]

# This target creates a production release image for the project.
FROM docker.mirror.hashicorp.services/alpine:3.20.1 as default

# PRODUCT_VERSION is the tag built, e.g. v0.1.0
# PRODUCT_REVISION is the git hash built
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=vault-k8s
ARG TARGETOS TARGETARCH

# Additional metadata labels used by container registries, platforms
# and certification scanners.
LABEL name="Vault K8s" \
      maintainer="Vault Team <vault@hashicorp.com>" \
      vendor="HashiCorp" \
      version=$PRODUCT_VERSION \
      release=$PRODUCT_VERSION \
      revision=$PRODUCT_REVISION \
      summary="The Vault-K8s binary includes first-class integrations between Vault and Kubernetes." \
      description="Vault-K8s includes first-class integrations between Vault and Kuberentes. Integrations include the Vault Agent Injector mutating admission webhook."

COPY LICENSE /licenses/mozilla.txt

# Create a non-root user to run the software.
RUN addgroup vault && \
    adduser -S -G vault vault

# Set up certificates, base tools, and software.
RUN set -eux && \
    apk update && \
    apk add --no-cache ca-certificates libcap su-exec iputils

COPY dist/$TARGETOS/$TARGETARCH/vault-k8s /bin/

USER vault
ENTRYPOINT ["/bin/vault-k8s"]

# This target creates a production ubi release image
# for the project for use on OpenShift.
FROM registry.access.redhat.com/ubi8/ubi-minimal:8.10-896.1717584414 as ubi

ARG PRODUCT_NAME
ARG PRODUCT_VERSION
ARG BIN_NAME
ARG PRODUCT_NAME=$BIN_NAME

# TARGETOS and TARGETARCH are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH

# Set ARGs as ENV so that they can be used in ENTRYPOINT/CMD
ENV PRODUCT_VERSION=$PRODUCT_VERSION
ENV BIN_NAME=$BIN_NAME

# Additional metadata labels used by container registries, platforms
# and certification scanners.
LABEL name="Vault K8s" \
      maintainer="Vault Team <vault@hashicorp.com>" \
      vendor="HashiCorp" \
      version=$PRODUCT_VERSION \
      release=$PRODUCT_VERSION \
      summary="The Vault-K8s binary includes first-class integrations between Vault and Kubernetes." \
      description="Vault-K8s includes first-class integrations between Vault and Kuberentes. Integrations include the Vault Agent Injector mutating admission webhook."

# Copy license for Red Hat certification.
COPY LICENSE /licenses/mozilla.txt

# Set up certificates and base tools.
RUN set -eux && \
    microdnf install -y ca-certificates gnupg openssl tzdata wget unzip procps shadow-utils

# Create a non-root user to run the software.
# On OpenShift, this will not matter since the container 
# is run as a random user and group. 
# This is just kept for consistency with our other images.
RUN groupadd --gid 1000 vault && \
    adduser --uid 100 --system -g vault vault && \
    usermod -a -G root vault

# Copy the CI-built binary of vault-k8s into /bin/
COPY dist/$TARGETOS/$TARGETARCH/$BIN_NAME /bin/

USER 100
ENTRYPOINT ["/bin/vault-k8s"]

# ===================================
#   Set default target to 'dev'.
# ===================================
FROM dev
