# === Build Stage ===
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/spectra-server ./cmd/spectra-server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/spectra-client ./cmd/spectra-client

# === Server Runtime ===
FROM alpine:3.20 AS server

RUN apk add --no-cache ca-certificates

COPY --from=builder /bin/spectra-server /usr/local/bin/spectra-server
COPY configs/ /etc/spectra/configs/

ENV SPECTRA_PROFILE=/etc/spectra/configs/profiles/geforcenow.json
ENV SPECTRA_LISTEN=:443

EXPOSE 443/udp

ENTRYPOINT ["spectra-server"]

# === Client Runtime ===
FROM alpine:3.20 AS client

RUN apk add --no-cache ca-certificates

COPY --from=builder /bin/spectra-client /usr/local/bin/spectra-client
COPY configs/ /etc/spectra/configs/

ENV SPECTRA_PROFILE=/etc/spectra/configs/profiles/geforcenow.json
ENV SPECTRA_SOCKS_LISTEN=:1080

EXPOSE 1080/tcp

ENTRYPOINT ["spectra-client"]
