# guardian/Dockerfile


# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create an isolated venv so runtime stage can copy just /venv
RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Copy and install dependencies first (layer-cached when requirements.txt unchanged)
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Runtime system deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    dnsutils \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Copy venv from builder — no compiler toolchain in runtime image
COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH"

# Copy application code
# guardian/data/ (wordlists etc.) is part of the package — no separate COPY needed.
# /app/data/ is the runtime database directory, created below and bind-mounted
# at runtime via docker-compose volumes so it is never baked into the image.
COPY guardian/ ./guardian/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Prepare runtime directories (logs + database) with correct permissions
RUN mkdir -p /app/logs /app/data

# Non-root user — entrypoint.sh fixes bind-mount ownership then drops to this user
RUN useradd -r -s /bin/false -u 1000 guardian && \
    chown -R guardian:guardian /app

EXPOSE 8888

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -sf http://localhost:8888/api/v1/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-m", "uvicorn", "guardian.api.main:app", \
     "--host", "0.0.0.0", "--port", "8888", "--workers", "1"]