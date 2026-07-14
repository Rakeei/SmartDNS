FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/smartdns ./cmd/smartdns

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/smartdns /usr/local/bin/smartdns
COPY config.yaml /etc/smartdns/config.yaml

EXPOSE 53/udp 53/tcp 80/tcp 443/tcp

ENTRYPOINT ["smartdns", "-config", "/etc/smartdns/config.yaml"]
