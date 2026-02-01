# Build from project root: podman build -f python/Dockerfile -t gdrive-python .
FROM ghcr.io/astral-sh/uv:python3.14-alpine

WORKDIR /app

# Copy dependency files
COPY python/pyproject.toml python/uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy application code
COPY python/main.py ./

# Copy web files for static serving
COPY web /srv/web

# Create non-root user for security (using high UID/GID to avoid conflicts)
RUN addgroup -g 10000 gdrive && \
    adduser -u 10000 -G gdrive -s /bin/sh -D gdrive && \
    chown -R gdrive:gdrive /app /srv/web

USER gdrive

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Start the token server
CMD ["uv", "run", "python", "main.py", "server", "--port", "8080"]
