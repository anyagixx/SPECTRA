# Changelog

## 0.2.0 - 2026-04-23

### Cryptographic Hardening
- Replaced `math/rand` with `crypto/rand` for padding byte generation in `Shaper.PadToTarget()` to prevent PRNG prediction attacks.
- Replaced simple auto-reset Bloom filter with a time-rotating dual-bucket Bloom filter aligned to `MaxTimestampDrift` (30s) for correct anti-replay semantics.
- Removed redundant `sync.Mutex` from `ServerVerifier` — the Bloom filter now manages its own internal synchronization.
- Added in-session key rotation (`CmdRekey`): client generates a fresh salt every 30 minutes, server derives new keys and echoes acknowledgment; both sides atomically switch `Encryptor`/`Decryptor`.

### Protocol Improvements
- Added application-level keepalive (`CmdKeepalive`): client sends keepalive every 20s, server echoes; dead tunnel detected and torn down after 60s of silence.
- Replaced `time.Sleep(100ms)` graceful close with proper QUIC stream FIN flush in both `ClientTunnel.Close()` and `ServerTunnel.Close()`.
- Added `CmdRekey` (0x06) command to the protocol framing layer.

### Active Probe Resistance
- Replaced HTTP/1.1 plaintext decoy with proper HTTP/3 binary framing (HEADERS + DATA frames with QPACK-encoded headers), making the decoy indistinguishable from a real H3 web server.

### Server Hardening
- Added connection concurrency semaphore (256 max) to the server accept loop to prevent DoS resource exhaustion.

### Code Quality
- Removed `DeriveSessionKeys` alias — only `DeriveSessionKeysDirect` remains.
- Inlined `dialViaSpectrum` into `dialViaSpectrumWithRequest`, eliminating an unnecessary indirection.
- Switched all error return paths in `crypto` and `handshake` packages to use sentinel errors (`ErrInvalidPSK`, `ErrInvalidSalt`, `ErrDecryption`, `ErrAuthFailed`, `ErrReplay`, `ErrVersionMismatch`) with `%w` wrapping for `errors.Is()` support.
- Documented `FlowFeatures` as reserved for future flow-level analysis evasion.

### Testing
- Added `TestBloomTimeRotation` verifying entries survive one rotation and expire after two.
- Added full E2E integration test (`TestIntegrationE2E`): QUIC server + handshake + client tunnel + upstream HTTP through the tunnel.

### Documentation
- Updated MVP roadmap in `SPECTRA-design.md` to reflect all completed phases and newly implemented features.

## 0.1.5 - 2026-04-23

- Hardened client reconnect handling: when the QUIC tunnel is lost, the SOCKS5 server now rejects new CONNECT requests until a fresh tunnel is established instead of sending them into a dead tunnel.
- Added a fast closed-tunnel guard in `DialTunnel` to prevent stale connection buildup during VPS redeploys or application connection storms.

## 0.1.4 - 2026-04-23

- Added `scripts/client-service.sh` for persistent Ubuntu Desktop installation as a `systemctl --user` service.
- Added `scripts/quic-tune.sh` to enable, disable, inspect, and restart client-side QUIC UDP buffer tuning without manual `/etc/sysctl.d` copying.
- Added `scripts/release-local.sh` to build local Linux `amd64`/`arm64` release archives and a source archive into `dist/`.
- Hardened server deployment by storing PSK and runtime paths in `/etc/spectra/spectra.env` instead of systemd process arguments.
- Fixed clean VPS deployment failures caused by missing `wget`/bootstrap tools, project path detection after Go installation, and over-broad rsync excludes.
- Fixed SOCKS5 tunnel cleanup by delegating `CloseWrite` to virtual tunnel connections, reducing stale connection buildup under aggressive clients.
- Updated `quic-go` to `v0.49.1`.
- Updated README and Russian HOWTO for the public GitHub repository `https://github.com/anyagixx/SPECTRA`.

## 0.1.3 - 2026-04-22

- Increased live TCP data frame sizes to the maximum protocol-supported wire budget, reducing framing and AEAD overhead on bulk transfers.
- Enlarged server upstream relay buffers to reduce syscall churn during sustained uploads and downloads.
- Added explicit QUIC flow-control tuning with larger stream and connection receive windows for long-lived proxy sessions.
- Added a regression test covering max-target fragmentation to keep large-frame transport behavior stable.

## 0.1.2 - 2026-04-22

- Removed per-chunk shaping sleeps from live tunneled TCP data so browser and file-transfer traffic no longer crawls under media-like pacing.
- Switched client upstream DATA frames to video-sized fragmentation so uploads are no longer constrained by tiny input-event packet sizes.
- Suppressed client-side padding generation while recent real data is in flight to keep padding from competing with active transfers.
- Hardened frame and upstream socket writes against short-write truncation, preventing partial TCP payload loss under sustained transfers.
- Verified end-to-end transfer against a VPS-local HTTP test service with successful `1 MiB` upload and download through the SOCKS proxy.

## 0.1.1 - 2026-04-22

- Replaced per-frame QUIC uni-stream creation with persistent send streams in each direction.
- Eliminated `too many open streams` failures under bursty browser and Telegram traffic.
- Kept frame handling ordered on long-lived streams so Firefox / Telegram style parallel connection bursts no longer exhaust stream credit.

## 0.1.0 - 2026-04-21

- Fixed SOCKS5 CONNECT replies for wrapped tunnel connections.
- Fixed tunnel decryption for out-of-order QUIC uni-stream delivery by binding decryption to frame sequence numbers.
- Serialized uni-stream frame handling on client and server to preserve TCP byte-stream ordering.
- Disabled padding on encrypted data frames until the wire format can carry explicit payload vs padding boundaries.
- Fixed traffic profile timing ranges so shaping no longer collapses to zero-delay loops.
- Preserved original FQDNs when dialing through the SOCKS5 tunnel to avoid client-side DNS leakage.
- Added regression tests for bundled profile delays, SOCKS5 reply serialization, FQDN preservation, and out-of-order frame decryption.
- Added CLI version reporting via `--version`.
