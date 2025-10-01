FROM python:3.11-slim

WORKDIR /app

# Install system dependencies with error handling
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    curl \
    git \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .


# Create necessary directories with proper permissions
RUN mkdir -p data logs && \
    chmod 755 data logs

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV GUARDIAN_PORT=8888

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8888/api/v1/health || exit 1

EXPOSE 8888

CMD ["uvicorn", "guardian.api.main:app", "--host", "0.0.0.0", "--port", "8888"]
