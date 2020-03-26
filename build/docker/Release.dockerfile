# This Dockerfile creates a production release image for the project. This
# downloads the release from releases.hashicorp.com and therefore requires that
# the release is published before building the Docker image.
#
# We don't rebuild the software because we want the exact checksums and
# binary signatures to match the software and our builds aren't fully
# reproducible currently.
FROM alpine:latest

# NAME and VERSION are the name of the software in releases.hashicorp.com
# and the version to download. Example: NAME=consul VERSION=1.2.3.
ARG NAME
ARG VERSION
ARG LOCATION

LABEL maintainer="Vault Team <vault@hashicorp.com>"
LABEL version=$VERSION

# Set ARGs as ENV so that they can be used in ENTRYPOINT/CMD
ENV NAME=$NAME
ENV VERSION=$VERSION

# This is the location of the releases.
ENV LOCATION=$LOCATION

# Create a non-root user to run the software.
RUN addgroup ${NAME} && \
    adduser -S -G ${NAME} ${NAME}

# Set up certificates, base tools, and software.
RUN set -eux && \
    apk add --no-cache ca-certificates curl gnupg libcap openssl su-exec iputils && \
    BUILD_GPGKEY=91A6E7F85D05C65630BEF18951852D87348FFC4C; \
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
    wget ${LOCATION}/${NAME}/${VERSION}/${NAME}_${VERSION}_linux_${ARCH}.zip && \
    wget ${LOCATION}/${NAME}/${VERSION}/${NAME}_${VERSION}_SHA256SUMS && \
    wget ${LOCATION}/${NAME}/${VERSION}/${NAME}_${VERSION}_SHA256SUMS.sig && \
    gpg --batch --verify ${NAME}_${VERSION}_SHA256SUMS.sig ${NAME}_${VERSION}_SHA256SUMS && \
    grep ${NAME}_${VERSION}_linux_${ARCH}.zip ${NAME}_${VERSION}_SHA256SUMS | sha256sum -c && \
    unzip -d /bin ${NAME}_${VERSION}_linux_${ARCH}.zip && \
    cd /tmp && \
    rm -rf /tmp/build && \
    apk del gnupg openssl && \
    rm -rf /root/.gnupg

USER ${NAME}
ENTRYPOINT /bin/${NAME}
