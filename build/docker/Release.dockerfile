# This Dockerfile creates a production release image for the project. This
# downloads the release from releases.hashicorp.com and therefore requires that
# the release is published before building the Docker image.
#
# We don't rebuild the software because we want the exact checksums and
# binary signatures to match the software and our builds aren't fully
# reproducible currently.
FROM docker.mirror.hashicorp.services/alpine:latest

# NAME and VERSION are the name of the software in releases.hashicorp.com
# and the version to download. Example: NAME=consul VERSION=1.2.3.
ARG VERSION
ARG LOCATION

# Additional metadata labels used by container registries, platforms
# and certification scanners.
LABEL name="Vault K8s" \
      maintainer="Vault Team <vault@hashicorp.com>" \
      vendor="HashiCorp" \
      version=$VERSION \
      release=$VERSION \
      summary="The Vault-K8s binary includes first-class integrations between Vault and Kubernetes." \
      description="Vault-K8s includes first-class integrations between Vault and Kuberentes. Integrations include the Vault Agent Injector mutating admission webhook."

# Set ARGs as ENV so that they can be used in ENTRYPOINT/CMD
ENV VERSION=$VERSION

# This is the location of the releases.
ENV LOCATION=$LOCATION

COPY LICENSE /licenses/mozilla.txt

# Create a non-root user to run the software.
RUN addgroup vault && \
    adduser -S -G vault vault

# Set up certificates, base tools, and software.
RUN set -eux && \
    apk add --no-cache ca-certificates gnupg libcap openssl su-exec iputils && \
    BUILD_GPGKEY=C874011F0AB405110D02105534365D9472D7468F; \
    found=''; \
    for server in \
        hkp://p80.pool.sks-keyservers.net:80 \
        hkp://keyserver.ubuntu.com:80 \
        hkp://pgp.mit.edu:80 \
    ; do \
        echo "Fetching GPG key $BUILD_GPGKEY from $server"; \
        gpg --keyserver "$server" --recv-keys "$BUILD_GPGKEY" && found=yes && break; \
    done; \
    test -z "$found" && echo >&2 "error: failed to fetch GPG key $BUILD_GPGKEY" && exit 1; \
    mkdir -p /tmp/build && \
    cd /tmp/build && \
    apkArch="$(apk --print-arch)" && \
    case "${apkArch}" in \
        aarch64) ARCH='arm64' ;; \
        armhf) ARCH='arm' ;; \
        x86) ARCH='386' ;; \
        x86_64) ARCH='amd64' ;; \
        *) echo >&2 "error: unsupported architecture: ${apkArch} (see ${LOCATION}/${NAME}/${VERSION}/)" && exit 1 ;; \
    esac && \
    wget ${LOCATION}/vault-k8s/${VERSION}/vault-k8s_${VERSION}_linux_${ARCH}.zip && \
    wget ${LOCATION}/vault-k8s/${VERSION}/vault-k8s_${VERSION}_SHA256SUMS && \
    wget ${LOCATION}/vault-k8s/${VERSION}/vault-k8s_${VERSION}_SHA256SUMS.sig && \
    gpg --batch --verify vault-k8s_${VERSION}_SHA256SUMS.sig vault-k8s_${VERSION}_SHA256SUMS && \
    grep vault-k8s_${VERSION}_linux_${ARCH}.zip vault-k8s_${VERSION}_SHA256SUMS | sha256sum -c && \
    unzip -d /bin vault-k8s_${VERSION}_linux_${ARCH}.zip && \
    cd /tmp && \
    rm -rf /tmp/build && \
    apk del gnupg openssl && \
    rm -rf /root/.gnupg

USER vault
ENTRYPOINT ["/bin/vault-k8s"]
