# Build from project root: podman build -f nodejs/Dockerfile -t gdrive-nodejs .
FROM node:22-alpine

ARG PORT=8080
ENV PORT=${PORT}

WORKDIR /app

# Copy package files and install dependencies
COPY nodejs/package*.json ./
RUN npm ci --only=production

# Copy application code
COPY nodejs/main.js ./

# Copy web files for static serving
COPY web /srv/web

# Create non-root user with home
RUN addgroup -g 10000 gdrive && \
    adduser -u 10000 -G gdrive -s /bin/sh -D -h /home/gdrive gdrive && \
    chown -R gdrive:gdrive /app /srv/web /home/gdrive

USER gdrive

EXPOSE ${PORT}

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:${PORT}/health || exit 1

CMD ["sh", "-c", "node main.js server --port $PORT"]
