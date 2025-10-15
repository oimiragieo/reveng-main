# REVENG Universal Reverse Engineering Platform - Production Docker Image
# ======================================================================

FROM python:3.14-slim as base

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
COPY setup.py pyproject.toml VERSION ./

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

# Multi-stage build for web interface
FROM node:18-alpine as web-builder

WORKDIR /app/web
COPY web_interface/package*.json ./
RUN npm install

# Install client dependencies
WORKDIR /app/web/client
COPY web_interface/client/package*.json ./
RUN npm install

# Copy all source files
WORKDIR /app/web
COPY web_interface/ ./

# Build the React client
WORKDIR /app/web/client
RUN npm run build

# Build the server
WORKDIR /app/web
RUN npm run build

# Final web interface image
FROM python:3.14-slim as web

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nginx \
    && rm -rf /var/lib/apt/lists/*

# Copy web build
COPY --from=web-builder /app/web/client/build /var/www/html

# Copy nginx config
COPY web_interface/nginx.conf /etc/nginx/nginx.conf

# Expose port
EXPOSE 80

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
