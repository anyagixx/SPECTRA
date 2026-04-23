# SPECTRA

**Steganographic Protocol for Encrypted Channels via Traffic-Realistic Adaptation**

SPECTRA is a QUIC/TLS 1.3 SOCKS5 proxy that tunnels client TCP traffic through a VPS while shaping packet sizes and timing toward a cloud-gaming traffic profile.

Current release baseline: `0.2.0`

## Features

- **QUIC/TLS 1.3 transport** over UDP, with HTTP/3-like ALPN.
- **SOCKS5 client interface** on `127.0.0.1:1080` by default.
- **XChaCha20-Poly1305 inner encryption** with HKDF-derived session keys.
- **PSK authentication and anti-replay** using HMAC-bound handshake data and a timestamp window.
- **Traffic camouflage** using the bundled GeForce NOW-style profile.
- **systemd deployment scripts** for a VPS server and Ubuntu Desktop client.
- **Managed QUIC tuning** with one-command enable, disable, status, and client restart.

## Quick Install

### Server: clean VPS

Prerequisites:

- A domain pointing to the VPS.
- A TLS certificate and private key for that domain.
- UDP `443` open at the VPS/firewall provider level.

```bash
sudo apt update
sudo apt install -y git ca-certificates

git clone https://github.com/anyagixx/SPECTRA.git /opt/spectra-src
cd /opt/spectra-src

sudo ./scripts/deploy-server.sh \
  --cert /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem \
  --key  /etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem
```

The server script installs missing base tools, installs Go if needed, builds `spectra-server`, generates a PSK if you did not pass `--psk`, applies QUIC sysctl tuning, creates `spectra.service`, and starts it.

Server secrets are stored in `/etc/spectra/spectra.env` with mode `600`; the PSK is not placed into the systemd `ExecStart` command line.

Useful server commands:

```bash
sudo systemctl status spectra
sudo journalctl -u spectra -f
sudo systemctl restart spectra
```

### Client: Ubuntu Desktop

```bash
git clone https://github.com/anyagixx/SPECTRA.git ~/SPECTRA
cd ~/SPECTRA

./scripts/client-service.sh install \
  --server YOUR_DOMAIN:443 \
  --sni YOUR_DOMAIN \
  --psk "PASTE_SERVER_PSK_HERE"

./scripts/quic-tune.sh enable
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me/ip
```

The client service stores its settings in `~/.config/spectra/client.env` with mode `600` and runs as the current desktop user via `systemctl --user`.

To avoid putting the PSK into shell history, you can pass it through `SPECTRA_PSK` instead of `--psk`.

Useful client commands:

```bash
./scripts/client-service.sh status
./scripts/client-service.sh logs
./scripts/client-service.sh restart
./scripts/client-service.sh stop
./scripts/client-service.sh uninstall
```

## QUIC Tuning

Do not manually copy sysctl files during normal use. Use the release helper:

```bash
./scripts/quic-tune.sh status
./scripts/quic-tune.sh enable
./scripts/quic-tune.sh disable
./scripts/quic-tune.sh restart-client
```

`enable` installs `deployments/sysctl/99-spectra-quic.conf` into `/etc/sysctl.d/`, reloads sysctl, saves the previous runtime values, and restarts `spectra-client` if it is active.

`disable` removes the persistent config, reloads sysctl, restores the saved runtime values when available, and restarts `spectra-client` if it is active.

## One-Shot Client

For temporary testing without a user service:

```bash
./scripts/run-client.sh \
  --server YOUR_DOMAIN:443 \
  --sni YOUR_DOMAIN \
  --psk "PASTE_SERVER_PSK_HERE"
```

Then configure a browser or application to use `SOCKS5 127.0.0.1:1080`.

## Local Release Build

Create local release archives in `dist/`:

```bash
./scripts/release-local.sh
ls -lh dist/
```

The script builds Linux `amd64` and `arm64` binary archives plus a source archive:

- `dist/spectra-v0.2.0-linux-amd64.tar.gz`
- `dist/spectra-v0.2.0-linux-arm64.tar.gz`
- `dist/spectra-v0.2.0-source.tar.gz`

`dist/` is intentionally ignored by git; GitHub should receive source, scripts, docs, and tags, not locally built artifacts unless you attach them to a GitHub Release manually.

## Manual Build

```bash
go build -o spectra-server ./cmd/spectra-server
go build -o spectra-client ./cmd/spectra-client
```

Run server:

```bash
./spectra-server \
  --psk <64-char-hex-psk> \
  --cert /path/to/cert.pem \
  --key /path/to/key.pem \
  --listen :443 \
  --profile configs/profiles/geforcenow.json
```

Run client:

```bash
./spectra-client \
  --psk <64-char-hex-psk> \
  --server your-domain.com:443 \
  --sni your-domain.com \
  --socks 127.0.0.1:1080 \
  --profile configs/profiles/geforcenow.json
```

## Configuration

All flags can be overridden via environment variables:

| Flag | Env Var | Description |
|------|---------|-------------|
| `--psk` | `SPECTRA_PSK` | Pre-shared key, 64 hex chars |
| `--listen` | `SPECTRA_LISTEN` | Server listen address |
| `--cert` | `SPECTRA_CERT` | TLS certificate path |
| `--key` | `SPECTRA_KEY` | TLS private key path |
| `--server` | `SPECTRA_SERVER` | Client server address |
| `--sni` | `SPECTRA_SNI` | Client TLS SNI hostname |
| `--socks` | `SPECTRA_SOCKS_LISTEN` | Client SOCKS5 listen address |
| `--profile` | `SPECTRA_PROFILE` | Traffic profile JSON path |

## Application Notes

For browser testing, prefer `curl --socks5-hostname` or Firefox/Chromium SOCKS5 settings first.

Telegram Desktop can open a very large number of concurrent SOCKS connections and IPv6 endpoints. Use it only after basic browser/curl tests pass, and restart `spectra-client` if an application creates a connection storm.

## Testing

```bash
go test ./...
go test -race ./...
```

Optional security check:

```bash
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

## Project Structure

```text
├── cmd/
│   ├── spectra-client/    # Client CLI entry point
│   └── spectra-server/    # Server CLI entry point
├── internal/
│   ├── camouflage/        # Traffic shaping
│   ├── crypto/            # XChaCha20-Poly1305, HKDF, HMAC
│   ├── handshake/         # PSK authentication, anti-replay
│   ├── protocol/          # Frame types, mux/demux
│   └── proxy/             # SOCKS5 server, tunnel, TCP dialer
├── configs/profiles/      # Traffic distribution profiles
├── deployments/           # Docker and sysctl configs
├── scripts/               # Deploy, client service, tuning, release helpers
└── docs/                  # Design document
```

## Design Document

See [docs/SPECTRA-design.md](docs/SPECTRA-design.md) for the technical specification.

## License

Research prototype. Use only on infrastructure and networks where you have permission to operate it.
