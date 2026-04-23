#!/usr/bin/env bash
# Generate a 32-byte (64 hex chars) pre-shared key for SPECTRA.
set -euo pipefail

PSK=$(openssl rand -hex 32)
echo ""
echo "=== SPECTRA PSK ==="
echo "$PSK"
echo "==================="
echo ""
echo "Save this key securely. You need the SAME key on both server and client."
