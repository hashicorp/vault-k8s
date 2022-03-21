FROM docker.mirror.hashicorp.services/alpine:latest as dev

RUN addgroup vault && \
    adduser -S -G vault vault

ADD dist/vault-k8s /vault-k8s

USER vault

ENTRYPOINT ["/vault-k8s"]

# This target creates a production release image for the project.
FROM docker.mirror.hashicorp.services/alpine:latest as default

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
    apk update && apk upgrade libretls && \
    apk add --no-cache ca-certificates libcap su-exec iputils

COPY dist/$TARGETOS/$TARGETARCH/vault-k8s /bin/

USER vault
ENTRYPOINT ["/bin/vault-k8s"]

# ===================================
#   Set default target to 'dev'.
# ===================================
FROM dev
