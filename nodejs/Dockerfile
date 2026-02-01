# Build from project root: podman build -f nodejs/Dockerfile -t gdrive-nodejs .
FROM node:22-alpine

WORKDIR /app

# Copy package files and install dependencies
COPY nodejs/package*.json ./
RUN npm ci --only=production

# Copy application code
COPY nodejs/main.js ./

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
CMD ["node", "main.js", "server", "--port", "8080"]
