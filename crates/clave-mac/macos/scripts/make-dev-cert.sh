#!/usr/bin/env bash
# make-dev-cert.sh — create a self-signed code-signing identity for LOCAL DEV ONLY.
#
# With SIP disabled (Track C, doc 14 §2.3) macOS honors the restricted Endpoint Security
# entitlement on an extension signed by this self-signed identity. This is NOT a shippable
# signing path — production needs a Developer ID + Apple's ES entitlement on a stock,
# SIP-enabled Mac (doc 14 §1.4, §5.4).
#
# Idempotent: re-running reuses the existing identity if already present.
set -euo pipefail

CN="Clave Dev Code Signing"
KEYCHAIN="${HOME}/Library/Keychains/login.keychain-db"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

if security find-identity -v -p codesigning | grep -q "$CN"; then
  echo "Identity '$CN' already present:"
  security find-identity -v -p codesigning | grep "$CN"
  exit 0
fi

echo "==> Generating self-signed code-signing cert '$CN'"
# CA:false leaf with a critical codeSigning EKU — exactly what codesign requires.
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout "$WORKDIR/dev.key" -out "$WORKDIR/dev.crt" \
  -subj "/CN=${CN}/O=Clave/C=US" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=critical,codeSigning" >/dev/null 2>&1

# OpenSSL 3 defaults to AES-256/SHA-256 PKCS12 MAC that Apple's `security import` cannot parse.
# Force legacy 3DES + SHA-1 MAC, and use a non-empty passphrase (Apple's importer mishandles the
# MAC on a no-password PKCS12).
P12PASS="clave-dev"
openssl pkcs12 -export -legacy \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
  -inkey "$WORKDIR/dev.key" -in "$WORKDIR/dev.crt" \
  -name "$CN" -out "$WORKDIR/dev.p12" -passout "pass:${P12PASS}"

echo "==> Importing into login keychain (allowing codesign to use the key)"
security import "$WORKDIR/dev.p12" -k "$KEYCHAIN" -P "$P12PASS" \
  -T /usr/bin/codesign -T /usr/bin/security >/dev/null

# Let codesign use the key non-interactively (no per-sign password prompt).
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "" "$KEYCHAIN" >/dev/null 2>&1 || true

echo "==> Trusting the cert for code signing (may prompt for your login password)"
# User trust domain — no sudo. If this errors under automation, run this script yourself.
security add-trusted-cert -r trustRoot -p codeSign "$WORKDIR/dev.crt" >/dev/null 2>&1 || \
  echo "   (trust step skipped/failed — codesign still works; verification just won't chain to a trusted root)"

echo "==> Result:"
security find-identity -v -p codesigning | grep "$CN" || {
  echo "ERROR: identity not found after import" >&2
  exit 1
}
