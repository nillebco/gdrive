# Build from project root: podman build -f python/Dockerfile -t gdrive-python .
FROM ghcr.io/astral-sh/uv:python3.14-alpine

ARG PORT=8000

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
    adduser -u 10000 -G gdrive -s /bin/sh -D -h /home/gdrive gdrive && \
    mkdir -p /home/gdrive/.cache/uv && \
    chown -R gdrive:gdrive /home/gdrive /app /srv/web

USER gdrive

ENV HOME=/home/gdrive
ENV PORT=${PORT}
EXPOSE ${PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Start the token server
CMD ["sh", "-c", "uv run --no-cache python main.py server --port $PORT"]
