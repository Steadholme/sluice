# syntax=docker/dockerfile:1

# ---- build stage: static, CGO-free binary -------------------------------------
FROM golang:1.26-alpine AS build
WORKDIR /src

# ca-certificates are copied into the scratch runtime so outbound TLS (e.g. to a
# Keystone behind HTTPS) works.
RUN apk add --no-cache ca-certificates

# Cache module downloads on an unchanged go.mod/go.sum.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Fully static binary so it runs on scratch. -trimpath + -s -w shrink it.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/sluice ./cmd/sluice

# ---- runtime stage: minimal, non-root scratch ---------------------------------
FROM scratch
WORKDIR /app

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/sluice /usr/local/bin/sluice
# A default config (static store, dev routes). Override by mounting your own and
# pointing -config at it, or by setting the env knobs.
COPY config.example.json /app/config.json

# Non-root numeric UID/GID; scratch has no /etc/passwd so a name is not usable.
USER 65532:65532

# Bind on all interfaces inside the container; the healthcheck probes loopback.
ENV LISTEN_ADDR=0.0.0.0:9090
EXPOSE 9090

# Self-probe /healthz with the built-in flag — no shell or wget needed on scratch.
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD ["/usr/local/bin/sluice", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/sluice"]
CMD ["-config", "/app/config.json"]
