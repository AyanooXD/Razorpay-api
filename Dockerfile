# syntax=docker/dockerfile:1.6

# Multi-stage build: build the binary in a full Go image, then ship only the
# binary + required text files in a tiny final image. Final image is ~15 MB
# vs. ~1 GB for a full golang image.

# ---------- stage 1: build ----------
FROM golang:1.24-alpine AS builder

# git is needed by go modules if any dependency is fetched via VCS.
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Cache module downloads: copy only go.mod first, download, then copy source.
COPY go.mod go.sum ./
RUN go mod download

COPY autorzp.go ./

# Build a stripped static binary so it works on any base (no libc dependency).
# -trimpath removes the build host's absolute paths from the binary.
# -ldflags="-s -w" strips the symbol table and DWARF debug info.
# CGO_ENABLED=0 ensures a fully static binary.
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -trimpath -ldflags="-s -w" -o /out/autorzp ./...

# ---------- stage 2: runtime ----------
FROM alpine:3.20

# ca-certificates: needed for HTTPS to api.razorpay.com
# tzdata: so time.Now() honors TZ env var if set
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S app && adduser -S app -G app

WORKDIR /app

# Copy the binary from the builder stage.
COPY --from=builder /out/autorzp /app/autorzp

# Copy the example data files. In production you'd mount these as volumes or
# bake them in via CI; keeping them in the image lets the container start
# standalone for testing.
COPY sites.txt px.txt /app/

# live.txt will be created at runtime; pre-create it so the volume mount point
# exists with correct ownership.
RUN touch /app/live.txt && chown -R app:app /app

USER app

# Default port matches the constant in autorzp.go (PORT env overrides).
ENV PORT=7070
EXPOSE 7070

# Healthcheck hits the /health endpoint we added in the fix.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:${PORT}/health || exit 1

ENTRYPOINT ["/app/autorzp"]
