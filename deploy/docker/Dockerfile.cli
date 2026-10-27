# =========================================================================
# Sentinel DevSecOps Unified Scanner - Hardened Container Image
# Multi-stage reproducible build with non-root security isolation
# =========================================================================

# Stage 1: Compile Go binaries matching go.mod (Go 1.27.3)
FROM golang:1.27.3-alpine3.20 AS builder

WORKDIR /src
RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=1.0.2

# Compile sentinel CLI and sentinel-agent daemon with stripped debug symbols
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /bin/sentinel ./cmd/sentinel && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/sentinel-agent ./cmd/sentinel-agent

# Install pinned govulncheck for Go reachability analysis
RUN CGO_ENABLED=0 go install golang.org/x/vuln/cmd/govulncheck@v1.1.4

# Stage 2: Hardened Runtime Environment
FROM alpine:3.24.3

ARG VERSION=1.0.2

LABEL org.opencontainers.image.title="Sentinel DevSecOps Unified Scanner" \
      org.opencontainers.image.description="Unified SAST, SCA, secrets, IaC, and resilience security scanner" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.authors="DraculaHub786" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/DraculaHub786/DevSecOps-Unified-Scanner"

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    git \
    curl \
    bash \
    jq \
    unzip \
    python3 \
    py3-pip

# Pinned engine versions matching plugins/versions.env
ENV GITLEAKS_VERSION=8.30.1 \
    OSV_VERSION=2.7.0 \
    TRIVY_VERSION=0.76.0 \
    NUCLEI_VERSION=3.3.8 \
    SEMGREP_VERSION=1.182.0 \
    PATH="/opt/venv/bin:$PATH"

# Setup Python virtual environment for Semgrep
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

# Copy checksums for cryptographic verification of downloads
COPY plugins/checksums.txt /opt/checksums.txt

# Install Gitleaks with SHA-256 integrity verification
RUN set -eu; \
    f="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    curl -fsSL -o "/tmp/$f" "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/$f"; \
    grep -F "  $f" /opt/checksums.txt | sed "s#  $f#  /tmp/$f#" | sha256sum -c -; \
    tar -xzf "/tmp/$f" -C /usr/local/bin gitleaks; \
    chmod 0755 /usr/local/bin/gitleaks; \
    rm -f "/tmp/$f"

# Install OSV-Scanner with SHA-256 integrity verification
RUN set -eu; \
    f="osv-scanner_linux_amd64"; \
    curl -fsSL -o "/tmp/$f" "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/$f"; \
    grep -F "  $f" /opt/checksums.txt | sed "s#  $f#  /tmp/$f#" | sha256sum -c -; \
    mv "/tmp/$f" /usr/local/bin/osv-scanner; \
    chmod 0755 /usr/local/bin/osv-scanner

# Install Trivy with SHA-256 integrity verification
RUN set -eu; \
    f="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    curl -fsSL -o "/tmp/$f" "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/$f"; \
    grep -F "  $f" /opt/checksums.txt | sed "s#  $f#  /tmp/$f#" | sha256sum -c -; \
    tar -xzf "/tmp/$f" -C /usr/local/bin trivy; \
    chmod 0755 /usr/local/bin/trivy; \
    rm -f "/tmp/$f"

# Install Nuclei with SHA-256 integrity verification
RUN set -eu; \
    f="nuclei_${NUCLEI_VERSION}_linux_amd64.zip"; \
    curl -fsSL -o "/tmp/$f" "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/$f"; \
    grep -F "  $f" /opt/checksums.txt | sed "s#  $f#  /tmp/$f#" | sha256sum -c -; \
    unzip -qo "/tmp/$f" -d /usr/local/bin nuclei; \
    chmod 0755 /usr/local/bin/nuclei; \
    rm -f "/tmp/$f"

# Copy compiled Sentinel binaries and govulncheck from builder
COPY --from=builder /bin/sentinel /usr/local/bin/sentinel
COPY --from=builder /bin/sentinel-agent /usr/local/bin/sentinel-agent
COPY --from=builder /go/bin/govulncheck /usr/local/bin/govulncheck

# Create isolated, unprivileged non-root user (UID 10001 / GID 10001)
RUN addgroup -g 10001 sentinel && \
    adduser -u 10001 -G sentinel -D -s /bin/sh sentinel && \
    mkdir -p /workspace /home/sentinel/.cache /home/sentinel/.semgrep && \
    chown -R sentinel:sentinel /workspace /home/sentinel /opt/venv

WORKDIR /workspace
USER 10001:10001

ENTRYPOINT ["/usr/local/bin/sentinel"]
CMD ["scan", "."]
