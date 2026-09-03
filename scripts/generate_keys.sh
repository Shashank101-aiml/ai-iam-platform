#!/usr/bin/env bash
# Generate RS256 PUBLIC/PRIVATE KEY PAIR for AI-IAM Platform JWT Token Signing.
#
# Filenames (private.pem / public.pem) and the default location
# (backend/keys) match app.core.config.Settings.JWT_PRIVATE_KEY_PATH /
# JWT_PUBLIC_KEY_PATH, which are resolved relative to the backend/
# working directory the app runs from (see docker/Dockerfile WORKDIR).
set -euo pipefail

KEY_DIR="${1:-backend/keys}"
mkdir -p "$KEY_DIR"

if [[ -f "$KEY_DIR/private.pem" ]]; then
  echo "⚠️  $KEY_DIR/private.pem already exists — refusing to overwrite." >&2
  echo "    Delete it first if you really want to rotate the signing key." >&2
  exit 1
fi

echo "Generating RS256 2048-bit private key..."
openssl genrsa -out "$KEY_DIR/private.pem" 2048

echo "Extracting public key from private key..."
openssl rsa -in "$KEY_DIR/private.pem" -pubout -out "$KEY_DIR/public.pem"

chmod 600 "$KEY_DIR/private.pem"
chmod 644 "$KEY_DIR/public.pem"

echo "✅ RS256 key pair successfully generated in $KEY_DIR:"
echo "   - Private Key: $KEY_DIR/private.pem"
echo "   - Public Key:  $KEY_DIR/public.pem"
