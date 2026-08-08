# REVENG Universal Reverse Engineering Platform - Production Docker Image
# ======================================================================

FROM python:3.9-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    git \
    curl \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r reveng && useradd -r -g reveng reveng

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY pyproject.toml VERSION ./

# Install REVENG package
RUN pip install -e .

# Create necessary directories
RUN mkdir -p /app/analysis /app/models /app/cache && \
    chown -R reveng:reveng /app

# Switch to non-root user
USER reveng

# Expose ports
EXPOSE 3000 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import reveng; print('REVENG is healthy')" || exit 1

# Default command
CMD ["reveng", "--help"]

# Multi-stage build for development
FROM base as development

# Install development dependencies
USER root
RUN pip install --no-cache-dir -r requirements-dev.txt
USER reveng

# Development command
CMD ["reveng", "serve", "--reload", "--host", "0.0.0.0", "--port", "3000"]
