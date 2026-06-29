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

# Pre-create the autocert cache dir so it can be COPYed into scratch with the
# right ownership (scratch has no shell to mkdir/chown at runtime).
RUN mkdir -p /acme

# ---- runtime stage: minimal, non-root scratch ---------------------------------
FROM scratch
WORKDIR /app

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/sluice /usr/local/bin/sluice
# A default config (static store, dev routes) used by the TLS_MODE=off smoke, plus
# the production Holdfast route table that fronts Keystone. Override by mounting
# your own and pointing -config at it, or by setting the env knobs.
COPY config.example.json /app/config.json
COPY config.holdfast.json /app/config.holdfast.json

# The autocert cache (issued certs + ACME account key), owned by the non-root
# runtime user and declared a volume so certificates survive container restarts
# (and avoid re-issuing against Let's Encrypt rate limits).
COPY --from=build --chown=65532:65532 /acme /acme
VOLUME /acme
ENV ACME_CACHE_DIR=/acme

# Non-root numeric UID/GID; scratch has no /etc/passwd so a name is not usable.
USER 65532:65532

# Bind on all interfaces inside the container; the healthcheck probes loopback.
# In TLS_MODE=off this is the single plain listener; in file/acme modes the
# gateway instead binds :80 (HTTP_ADDR) and :443 (HTTPS_ADDR).
ENV LISTEN_ADDR=0.0.0.0:9090
EXPOSE 80 443 9090

# Self-probe /healthz with the built-in flag — no shell or wget needed on scratch.
# The probe follows TLS_MODE: off -> http on LISTEN_ADDR; file/acme -> https on
# HTTPS_ADDR (verification skipped for the loopback dial).
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD ["/usr/local/bin/sluice", "-healthcheck"]

ENTRYPOINT ["/usr/local/bin/sluice"]
CMD ["-config", "/app/config.json"]
