FROM apify/actor-python:3.13

USER root

# Install git + ca-certificates + curl (for betterleaks download)
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Download + install the upstream betterleaks binary (pinned version).
# Latest release at build time: v1.3.1 (published 2026-05-22).
ARG BETTERLEAKS_VERSION=1.3.1
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64) BL_ARCH="x64" ;; \
        arm64) BL_ARCH="arm64" ;; \
        *) echo "unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    curl -sSfL "https://github.com/betterleaks/betterleaks/releases/download/v${BETTERLEAKS_VERSION}/betterleaks_${BETTERLEAKS_VERSION}_linux_${BL_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin betterleaks && \
    chmod +x /usr/local/bin/betterleaks && \
    betterleaks version

USER myuser

COPY --chown=myuser:myuser requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=myuser:myuser . ./

CMD ["python3", "-m", "src.main"]
