# SPECTRA — Technical Design Document

**Steganographic Protocol for Encrypted Channels via Traffic-Realistic Adaptation**

Version: 0.1.0-draft
Date: 2026-04-20

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Threat Model](#2-threat-model)
3. [Novel Camouflage Vector](#3-novel-camouflage-vector)
4. [Cryptographic Design](#4-cryptographic-design)
5. [Handshake Protocol](#5-handshake-protocol)
6. [Packet Format & Framing](#6-packet-format--framing)
7. [Traffic Shaping — Anti-ML DPI](#7-traffic-shaping--anti-ml-dpi)
8. [Active Probe Resistance](#8-active-probe-resistance)
9. [Architecture](#9-architecture)
10. [Deployment](#10-deployment)
11. [Performance Analysis](#11-performance-analysis)
12. [MVP Roadmap](#12-mvp-roadmap)

---

## 1. Executive Summary

SPECTRA is a next-generation anti-censorship proxy protocol that tunnels arbitrary TCP traffic inside QUIC streams statistically indistinguishable from cloud gaming traffic (GeForce NOW, Xbox Cloud Gaming). It combines:

- **Outer camouflage**: Standard QUIC/TLS 1.3 with legitimate certificates, cloud-gaming-like ALPN and SNI
- **Inner encryption**: XChaCha20-Poly1305 with HKDF-derived keys
- **Traffic shaping**: Packet-length and inter-arrival-time distributions matched to real cloud gaming statistical profiles using Markov-chain models
- **Active probe immunity**: HMAC-bound challenge-response handshake with decoy web server fallback

The result is a proxy whose traffic is indistinguishable from legitimate cloud gaming sessions at the network, statistical, and behavioral layers.

---

## 2. Threat Model

### Adversary Capabilities
| Capability | Level |
|---|---|
| Passive packet capture | Full |
| TLS metadata inspection (SNI, ALPN, cert chain) | Full |
| ML-based traffic classification (packet sizes, IATs, flow features) | Advanced |
| Active probing (replay, connect-and-probe) | Full |
| IP reputation / AS-level blocking | Partial |

### Out of Scope
- Endpoint compromise (malware on client/server)
- Rubber-hose cryptanalysis
- Global traffic correlation (Tor-level adversary)

### Security Goals
1. **Indistinguishability**: Network observer cannot distinguish SPECTRA sessions from real cloud gaming sessions with probability > 1/2 + ε for negligible ε
2. **Probe resistance**: Active probes receive only legitimate web server responses
3. **Forward secrecy**: Compromise of long-term PSK does not reveal past session data
4. **Replay immunity**: Captured handshake tokens cannot be replayed

---

## 3. Novel Camouflage Vector

### Why Cloud Gaming?

Cloud gaming traffic is an ideal camouflage vector because:

1. **High bandwidth** — sustained 10-50 Mbps streams are normal, accommodating real proxy traffic without anomalous volume
2. **Bidirectional** — both upstream (input commands) and downstream (video/audio) carry significant data
3. **QUIC-native** — GeForce NOW uses QUIC, providing a natural protocol match
4. **Uncensorable** — blocking cloud gaming impacts millions of legitimate users and major corporations (NVIDIA, Microsoft)
5. **Encrypted** — all cloud gaming traffic is already fully encrypted, so encrypted payloads are expected

### Multi-Stream Architecture

SPECTRA multiplexes proxy traffic across three QUIC stream types that mirror cloud gaming channels:

```
┌─────────────────────────────────────────────────┐
│                QUIC Connection                   │
│                                                  │
│  Stream 0x00  ─── Control Channel (bidirectional)│
│  Stream 0x04  ─── "Video" (server → client)      │
│  Stream 0x08  ─── "Audio" (server → client)      │
│  Stream 0x0C  ─── "Input" (client → server)      │
│  Stream 0x10+ ─── Additional data streams         │
└─────────────────────────────────────────────────┘
```

- **Video stream**: Carries bulk downstream proxy data, chunked into frames mimicking H.264/H.265 NAL unit sizes (typical: 1200-1400 bytes with periodic I-frame bursts of 4000-8000 bytes)
- **Audio stream**: Carries small periodic downstream data, mimicking Opus audio frames (typical: 40-160 bytes at ~20ms intervals)
- **Input stream**: Carries upstream proxy data, mimicking HID input events (typical: 20-80 bytes, bursty)
- **Control stream**: Handshake, keepalive, session management

---

## 4. Cryptographic Design

### Key Hierarchy

```
PSK (Pre-Shared Key, 256-bit)
 │
 ├─ HKDF-Extract(PSK, connection_salt)
 │   │
 │   └─ HKDF-Expand("spectra-session-key", 32) → Session Key (Ks)
 │   └─ HKDF-Expand("spectra-session-iv",  24) → Session Base IV
 │
 └─ Session Key (Ks) used for XChaCha20-Poly1305
     │
     ├─ Video  stream nonce: Base_IV ⊕ (0x01 || counter_48bit)
     ├─ Audio  stream nonce: Base_IV ⊕ (0x02 || counter_48bit)
     ├─ Input  stream nonce: Base_IV ⊕ (0x03 || counter_48bit)
     └─ Control stream nonce: Base_IV ⊕ (0x00 || counter_48bit)
```

### Why XChaCha20-Poly1305?

- **24-byte nonce**: Eliminates nonce collision risk even across long sessions
- **No AES-NI dependency**: Consistent performance across ARM/x86
- **AEAD**: Authenticated encryption prevents tampering
- **Speed**: ~5 Gbps on modern CPUs in software

### Forward Secrecy

Each connection generates a fresh `connection_salt` (32 random bytes from the client). Combined with the PSK via HKDF, this produces unique session keys. Even if the PSK is later compromised, past `connection_salt` values (ephemeral, never stored) cannot be recovered.

---

## 5. Handshake Protocol

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    Note over C,S: QUIC TLS 1.3 Handshake (standard)
    C->>S: QUIC ClientHello (SNI: gaming.example.com, ALPN: h3)
    S->>C: QUIC ServerHello + Certificate + Finished

    Note over C,S: SPECTRA Auth (over Control Stream 0x00)
    C->>S: AUTH_INIT {version, connection_salt, timestamp, HMAC(PSK, salt||ts)}
    S->>S: Verify HMAC, check timestamp within ±30s window
    alt Valid Auth
        S->>C: AUTH_OK {server_random, HMAC(PSK, salt||server_random)}
        Note over C,S: Both derive Session Key via HKDF
        C->>S: AUTH_CONFIRM {E(Ks, "SPECTRA-READY")}
        Note over C,S: Tunnel established — begin proxying
    else Invalid Auth (probe detected)
        S->>C: HTTP/3 Response: 403 Forbidden (or gaming landing page)
        S->>S: Close connection after decoy response
    end
```

### Anti-Replay Mechanism

1. **Timestamp window**: Server rejects `AUTH_INIT` if `|server_time - timestamp| > 30s`
2. **Nonce cache**: Server maintains a Bloom filter of seen `(connection_salt, timestamp)` pairs for the 60s window. Duplicate = reject.
3. **HMAC binding**: `HMAC-SHA256(PSK, connection_salt || timestamp)` — cannot be forged without PSK, cannot be replayed outside the time window (Bloom filter prevents within-window replay)

---

## 6. Packet Format & Framing

### SPECTRA Frame (inside QUIC stream payload)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Type (8)   |  Flags (8)    |       Payload Length (16)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (32)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|              Encrypted Payload (variable)                     |
|                   + Poly1305 Tag (16 bytes)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              Padding (variable, 0-N bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Frame Types

| Type | Value | Direction | Description |
|------|-------|-----------|-------------|
| VIDEO_FRAME | 0x01 | S→C | Bulk downstream data (mimics video) |
| AUDIO_FRAME | 0x02 | S→C | Small periodic downstream data |
| INPUT_FRAME | 0x03 | C→S | Upstream data (mimics input) |
| CONTROL | 0x00 | Both | Handshake, keepalive, metadata |
| PADDING | 0xFF | Both | Pure padding frame (no payload) |

### Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0 | KEY_FRAME | Mimics I-frame (allows larger packet) |
| 1 | HAS_PADDING | Padding bytes appended after tag |
| 2-7 | Reserved | Must be zero |

### Decrypted Payload Structure

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Cmd (8)  | Data Length (16)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Data (variable)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Commands: `CONNECT(0x01)`, `DATA(0x02)`, `CLOSE(0x03)`, `KEEPALIVE(0x04)`

---

## 7. Traffic Shaping — Anti-ML DPI

### The Problem

Modern DPI uses ML classifiers trained on flow-level features:
- **Packet length distribution** (mean, variance, histogram)
- **Inter-arrival time (IAT) distribution**
- **Burst patterns** (packets per burst, burst duration)
- **Byte ratio** (upstream vs downstream)

### SPECTRA's Defense: Statistical Profile Matching

We model real cloud gaming traffic as a statistical profile and shape SPECTRA traffic to match.

#### 7.1 Packet Length Distribution

Let `P_real` be the empirical packet length distribution of GeForce NOW traffic, and `P_spectra` be SPECTRA's output distribution.

**Goal**: Minimize the Kullback-Leibler divergence:

```
D_KL(P_real || P_spectra) = Σ P_real(x) · log(P_real(x) / P_spectra(x)) < ε
```

**Method**: For each proxy data chunk of size `n`:
1. Sample a target frame size `t` from `P_real` conditioned on `t ≥ n + overhead`
2. Pad the frame to exactly `t` bytes
3. If `n + overhead > max(P_real)`, fragment into multiple frames

This ensures every emitted packet has a size drawn from `P_real`.

#### 7.2 Inter-Arrival Time (IAT) Matching

Cloud gaming traffic exhibits quasi-periodic patterns:
- Video frames: ~16.67ms intervals (60 FPS) with jitter σ ≈ 2ms
- Audio frames: ~20ms intervals with jitter σ ≈ 1ms
- Input events: Poisson-distributed, λ ≈ 125 events/sec (8ms mean)

We model IATs as a **Markov chain** with states representing traffic phases:

```
States: {Idle, VideoFrame, AudioFrame, InputBurst, IFrame}

Transition matrix T (example):
         Idle  Video  Audio  Input  IFrame
Idle   [ 0.10  0.50   0.20   0.15   0.05 ]
Video  [ 0.05  0.55   0.20   0.15   0.05 ]
Audio  [ 0.05  0.50   0.20   0.20   0.05 ]
Input  [ 0.10  0.50   0.20   0.15   0.05 ]
IFrame [ 0.05  0.60   0.20   0.10   0.05 ]
```

Each state has an associated IAT distribution (Gaussian or Gamma). The shaper:
1. Steps the Markov chain to decide the next frame type
2. Samples the IAT from the state's distribution
3. Waits that duration, then sends the frame

If real proxy data is available, it fills the frame. Otherwise, a PADDING frame is sent.

#### 7.3 Formal Indistinguishability Argument

**Theorem (informal)**: Let `C` be any polynomial-time ML classifier. If SPECTRA's traffic shaper produces packet sequences whose joint distribution over (packet_size, IAT) has total variation distance ≤ δ from real cloud gaming traffic, then:

```
|Pr[C(SPECTRA) = 1] - Pr[C(RealGaming) = 1]| ≤ δ
```

By construction, δ is bounded by the KL-divergence of our shaping distributions, which we target at < 0.01 (measured via offline KS-tests against captured cloud gaming traffic).

#### 7.4 Kolmogorov-Smirnov Test Validation

During development, we validate by:
1. Capturing N=10,000 packets of real GeForce NOW traffic
2. Capturing N=10,000 packets of SPECTRA traffic
3. Running two-sample KS test on packet lengths and IATs
4. **Pass criterion**: p-value > 0.05 (cannot reject null hypothesis that distributions are identical)

---

## 8. Active Probe Resistance

### Attack Vectors & Defenses

| Attack | Defense |
|--------|---------|
| **Connect and observe** | Server serves legitimate HTTP/3 gaming landing page to unauthenticated clients |
| **Replay AUTH_INIT** | Bloom filter + timestamp window rejects duplicate (salt, timestamp) pairs |
| **Forge AUTH_INIT** | HMAC-SHA256 requires PSK knowledge; brute-force infeasible (2^256) |
| **Timing side-channel on auth** | Constant-time HMAC comparison; fixed-delay decoy response |
| **Certificate probe** | Real Let's Encrypt certificate for a real domain; indistinguishable from any H3 site |

### Decoy Behavior

When the server receives an unauthenticated QUIC connection:

```
1. Accept QUIC connection normally (TLS 1.3 completes)
2. Wait for first stream data
3. If no valid AUTH_INIT within 5s:
   → Serve HTTP/3 response: HTML page for "CloudPlay™ Gaming Service"
   → Include realistic headers (Server: nginx/1.25, Content-Type: text/html)
   → Close after response
4. If invalid AUTH_INIT:
   → Same decoy behavior (no error differentiation)
```

This makes the server indistinguishable from a real web server to any probe.

---

## 9. Architecture

### System Architecture

```mermaid
graph LR
    subgraph Client Machine
        APP[Application] -->|TCP| SOCKS5[SOCKS5 Server :1080]
        SOCKS5 --> ENC[Payload Encryptor]
        ENC --> SHAPER[Traffic Shaper]
        SHAPER -->|QUIC streams| QCLIENT[QUIC Client]
    end

    QCLIENT ==>|Internet QUIC/443| QSERVER

    subgraph Server Machine
        QSERVER[QUIC Server :443] --> DESHAPER[Traffic Deshaper]
        DESHAPER --> DEC[Payload Decryptor]
        DEC --> DIALER[TCP Dialer]
        DIALER -->|TCP| UPSTREAM[Upstream Servers]
    end
```

### Data Flow (Client → Server)

```
1. App sends TCP data to SOCKS5 proxy (localhost:1080)
2. SOCKS5 handler reads destination, sends CONNECT to server
3. Payload encryptor:
   a. Wraps data in SPECTRA inner frame (Cmd=DATA, length, data)
   b. Encrypts with XChaCha20-Poly1305 (session key, stream nonce)
4. Traffic shaper:
   a. Queries Markov chain for next frame type & timing
   b. Pads encrypted frame to target size from P_real
   c. Wraps in SPECTRA outer frame (Type=INPUT_FRAME, flags, seq, payload+tag+padding)
   d. Waits for IAT timer, then sends on QUIC Input stream
5. QUIC client sends on wire
```

### Data Flow (Server → Client)

```
1. Server receives upstream TCP response
2. Payload encryptor wraps + encrypts (same as above)
3. Traffic shaper selects VIDEO_FRAME or AUDIO_FRAME type
   - Large responses → VIDEO_FRAME (with periodic I-frame flags)
   - Small responses → AUDIO_FRAME
4. Pads and schedules per Markov chain timing
5. Sends on QUIC Video/Audio streams
```

---

## 10. Deployment

### Docker Compose — Server

```yaml
version: "3.8"
services:
  spectra-server:
    build:
      context: .
      dockerfile: deployments/Dockerfile
      target: server
    ports:
      - "443:443/udp"
    environment:
      - SPECTRA_PSK=${SPECTRA_PSK}
      - SPECTRA_DOMAIN=${SPECTRA_DOMAIN}
      - SPECTRA_CERT_DIR=/certs
      - SPECTRA_PROFILE=geforcenow
      - SPECTRA_LISTEN=:443
    volumes:
      - ./certs:/certs:ro
      - spectra-data:/data
    restart: unless-stopped

volumes:
  spectra-data:
```

### Docker Compose — Client

```yaml
version: "3.8"
services:
  spectra-client:
    build:
      context: .
      dockerfile: deployments/Dockerfile
      target: client
    ports:
      - "1080:1080/tcp"
    environment:
      - SPECTRA_PSK=${SPECTRA_PSK}
      - SPECTRA_SERVER=${SPECTRA_SERVER}
      - SPECTRA_SNI=${SPECTRA_SNI}
      - SPECTRA_PROFILE=geforcenow
      - SPECTRA_SOCKS_LISTEN=:1080
    restart: unless-stopped
```

### Quick Start

```bash
# Server
export SPECTRA_PSK=$(openssl rand -hex 32)
export SPECTRA_DOMAIN=gaming.example.com
docker compose -f deployments/docker-compose.server.yml up -d

# Client (on a different machine)
export SPECTRA_PSK=<same-psk-as-server>
export SPECTRA_SERVER=gaming.example.com:443
export SPECTRA_SNI=gaming.example.com
docker compose -f deployments/docker-compose.client.yml up -d

# Configure browser/app to use SOCKS5 proxy at localhost:1080
```

---

## 11. Performance Analysis

### Latency Overhead

| Component | Added Latency |
|-----------|---------------|
| QUIC TLS 1.3 handshake | 1 RTT (0-RTT with resumption) |
| SPECTRA auth handshake | 1 RTT (~1 additional round trip) |
| Traffic shaping IAT jitter | 0-16ms (video frame interval) |
| XChaCha20 encryption | < 0.1ms per frame |
| **Total added (steady state)** | **~5-16ms** |

### CPU Overhead

| Operation | Throughput (single core) |
|-----------|------------------------|
| XChaCha20-Poly1305 encrypt | ~3-5 Gbps |
| HKDF key derivation | ~1M ops/sec |
| Markov chain step | ~100M ops/sec (negligible) |
| Padding computation | ~100M ops/sec (negligible) |

**Bottleneck**: Encryption at ~4 Gbps per core. For a typical proxy session (50 Mbps), CPU overhead is < 2%.

### Bandwidth Overhead

| Source | Overhead |
|--------|----------|
| SPECTRA frame header | 8 bytes per frame |
| Poly1305 auth tag | 16 bytes per frame |
| Padding (distribution matching) | ~10-25% of payload |
| Padding frames (idle shaping) | ~5-15 Kbps during idle |
| **Total** | **~15-30%** |

### Theoretical Limits

- **Max throughput**: Bounded by QUIC congestion control and single-core encryption (~4 Gbps)
- **Min latency**: 1 RTT + shaping jitter floor. Cannot go below ~5ms added.
- **Connection density**: ~10,000 concurrent sessions per server (limited by QUIC state, ~1KB per session)

---

## 12. MVP Roadmap

### Phase 1: Core Protocol (Weeks 1-2)
- [x] Crypto module (HKDF, XChaCha20-Poly1305)
- [x] Frame serialization/deserialization
- [x] QUIC connection setup with quic-go
- [x] Basic handshake (PSK auth, no traffic shaping)
- [x] End-to-end data tunnel (no SOCKS5 yet, raw TCP forwarding)

### Phase 2: Proxy Layer (Week 3)
- [x] SOCKS5 server on client side
- [x] TCP dialer on server side
- [x] Connection multiplexing (multiple SOCKS5 connections over one QUIC session)

### Phase 3: Camouflage (Weeks 4-5)
- [x] GeForce NOW traffic profile (captured/synthesized JSON)
- [x] Packet length padding engine (crypto/rand)
- [x] IAT Markov chain shaper
- [x] Padding frame generator for idle periods

### Phase 4: Hardening (Week 6)
- [x] Anti-replay Bloom filter (time-rotating dual-bucket)
- [x] Decoy web server (HTTP/3 binary framing)
- [x] Constant-time auth comparison
- [x] Connection rate limiter (256 concurrent connections)
- [x] Session key rotation (CmdRekey every 30 min)
- [x] Application-level keepalive with dead-tunnel detection
- [x] Graceful close (stream FIN flush)
- [ ] Connection migration support

### Phase 5: DevOps (Week 7)
- [x] Multi-stage Dockerfile
- [x] Docker Compose for client & server
- [ ] Auto-TLS with ACME
- [x] Configuration management (env vars, config file)

### Phase 6: Validation (Week 8)
- [x] Unit tests for all modules
- [x] Integration test (client → server → upstream HTTP)
- [ ] KS-test validation against traffic profiles
- [ ] Active probe testing
