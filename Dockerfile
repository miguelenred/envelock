# Envelock loader on PHP 8.3, ready to try in one command. The loader is the official prebuilt
# release binary (built on glibc 2.28 with OpenSSL 3 linked in, so it loads on this image's newer
# glibc with no system OpenSSL). This image ships NO keys: it is a generic loader. To run protected
# code, mount your identity file and point envelock.identity at it, e.g.:
#
#   docker run --rm -v "$PWD/identity.bin:/etc/envelock/identity.bin:ro" \
#     -e PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d \
#     ghcr.io/miguelenred/envelock php -d envelock.identity=/etc/envelock/identity.bin your-app.php
#
# Build: docker build --build-arg ENVELOCK_VERSION=1.1.2 -t envelock .
FROM php:8.3-cli-bookworm

ARG ENVELOCK_VERSION=1.1.2
LABEL org.opencontainers.image.source="https://github.com/miguelenred/envelock" \
      org.opencontainers.image.description="PHP 8.3 CLI with the Envelock loader (offline PHP source protection) preinstalled. Generic loader, no embedded keys — mount your identity.bin and set envelock.identity." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${ENVELOCK_VERSION}"

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl unzip; \
    rm -rf /var/lib/apt/lists/*; \
    asset="php_envelock-${ENVELOCK_VERSION}_php8.3-x86_64-linux-glibc-nts.zip"; \
    url="https://github.com/miguelenred/envelock/releases/download/${ENVELOCK_VERSION}/${asset}"; \
    curl -fsSL "$url" -o /tmp/envelock.zip; \
    mkdir -p /tmp/envelock; unzip -o /tmp/envelock.zip -d /tmp/envelock; \
    so="$(find /tmp/envelock -name 'envelock.so' | head -1)"; \
    test -n "$so"; \
    cp "$so" "$(php -r 'echo ini_get("extension_dir");')/envelock.so"; \
    docker-php-ext-enable envelock; \
    rm -rf /tmp/envelock /tmp/envelock.zip; \
    php --ri envelock

CMD ["php", "--ri", "envelock"]
