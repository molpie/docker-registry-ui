###############################
#        BUILDER STAGE        #
###############################
FROM python:3.13-alpine3.22 AS builder

WORKDIR /app

# Install tools required only during build
RUN apk add --no-cache curl tar ca-certificates

# Detect system architecture and download the latest stable Trivy release
RUN ARCH="$(apk --print-arch)"; \
    case "$ARCH" in \
        x86_64)   TRIVY_ARCH="64bit" ;; \
        aarch64)  TRIVY_ARCH="ARM64" ;; \
        armv7)    TRIVY_ARCH="ARM" ;; \
        ppc64le)  TRIVY_ARCH="PPC64LE" ;; \
        s390x)    TRIVY_ARCH="s390x" ;; \
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
    esac && \
    TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest \
        | grep tag_name | cut -d '"' -f 4) && \
    echo "Downloading Trivy $TRIVY_VERSION for $TRIVY_ARCH" && \
    curl -L -s \
        "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION#v}_Linux-${TRIVY_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin trivy && \
    chmod +x /usr/local/bin/trivy

# Install Python dependencies into a separate directory
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


###############################
#        RUNTIME STAGE        #
###############################
FROM python:3.13-alpine3.22 AS runtime

WORKDIR /app

# Copy Trivy binary from builder stage
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy

# Copy installed Python packages
COPY --from=builder /install /usr/local

# Copy application source code
COPY app/ ./app/
COPY templates/ ./templates/
COPY static/ ./static/
COPY asgi.py .

EXPOSE 5000

CMD ["uvicorn", "asgi:app", "--host", "0.0.0.0", "--port", "5000", "--workers", "4", "--log-level", "info", "--access-log"]