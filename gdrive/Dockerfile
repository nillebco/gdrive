# ---------- BUILDER ----------
FROM ghcr.io/astral-sh/uv:python3.14-alpine AS builder

WORKDIR /app

# Install build deps only in builder
RUN apk add --no-cache build-base

COPY python/pyproject.toml python/uv.lock ./

# Create project venv in /app/.venv
RUN uv sync --frozen --no-dev

COPY python/main.py ./


# ---------- RUNTIME ----------
FROM python:3.14-alpine

ARG PORT=8000
ENV PORT=${PORT}

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/main.py ./

# Static files
COPY web /srv/web

# Create non-root user with home
RUN addgroup -g 10000 gdrive && \
    adduser -u 10000 -G gdrive -s /bin/sh -D -h /home/gdrive gdrive && \
    chown -R gdrive:gdrive /app /srv/web /home/gdrive

USER gdrive

# Use venv Python directly
ENV PATH="/app/.venv/bin:$PATH"

EXPOSE ${PORT}

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/health || exit 1

CMD ["sh", "-c", "python main.py server --port $PORT"]
