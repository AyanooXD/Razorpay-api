# syntax=docker/dockerfile:1.6

# Multi-stage build
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

# Copy ONLY autorzp.go (latest version with all fixes)
COPY autorzp.go ./

RUN go build -trimpath -ldflags="-s -w" -o /out/autorzp ./...

# ---------- stage 2: runtime ----------
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S app && adduser -S app -G app

WORKDIR /app

COPY --from=builder /out/autorzp /app/autorzp

# Bundle default data files as seeds — copied to /data/ at first startup
# (entrypoint script copies them only if /data/ files don't exist yet,
#  so Railway persistent volume data is never overwritten on redeploy)
COPY sites.txt px.txt /app/seeds/

RUN touch /app/seeds/live.txt && \
    mkdir -p /data && \
    chown -R app:app /app /data

USER app

ENV PORT=7070
EXPOSE 7070

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:${PORT}/health || exit 1

# Entrypoint: seed /data/ from bundled defaults on first deploy,
# then start the server
ENTRYPOINT ["/bin/sh", "-c", "\
  if [ ! -f /data/sites.txt ]; then cp /app/seeds/sites.txt /data/sites.txt; fi; \
  if [ ! -f /data/px.txt ];    then cp /app/seeds/px.txt    /data/px.txt;    fi; \
  if [ ! -f /data/live.txt ];  then touch /data/live.txt;                    fi; \
  exec /app/autorzp"]
