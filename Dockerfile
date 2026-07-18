FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/smartdns ./cmd/smartdns

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/smartdns /usr/local/bin/smartdns
# config.yaml, domains.txt, and allowed_ips.txt are per-server runtime data
# (gitignored, never in the build context) — they're supplied entirely via
# the bind mounts in docker-compose.yml, not baked into the image.
WORKDIR /etc/smartdns

EXPOSE 53/udp 53/tcp 80/tcp 443/tcp

ENTRYPOINT ["smartdns", "-config", "/etc/smartdns/config.yaml"]
