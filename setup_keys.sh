#!/usr/bin/env bash
# Generate an RSA-4096 CA, an EC P-256 recipient key, a CSR, and a CA-signed
# certificate, then extract the EC public key from the certificate.
#
# Usage:  bash setup_keys.sh [output-dir]
#         (output-dir defaults to the current directory)

set -euo pipefail

OUTDIR="${1:-.}"
mkdir -p "$OUTDIR"

# ── 1. RSA-4096 CA key ────────────────────────────────────────────────────────
echo "[1] Generating RSA-4096 CA private key …"
openssl genrsa -out "$OUTDIR/ca-key.pem" 4096
chmod 600 "$OUTDIR/ca-key.pem"

# ── 2. CA self-signed certificate (10 years) ─────────────────────────────────
echo "[2] Self-signing CA certificate …"
openssl req -new -x509 \
  -key    "$OUTDIR/ca-key.pem" \
  -out    "$OUTDIR/ca-cert.pem" \
  -days   3650 \
  -subj   "/CN=Tutorial RSA CA/O=Example/C=US"

# ── 3. EC P-256 recipient key (Bob) ──────────────────────────────────────────
echo "[3] Generating EC P-256 recipient key …"
openssl ecparam -name prime256v1 -genkey -noout \
  -out "$OUTDIR/recipient-key.pem"
chmod 600 "$OUTDIR/recipient-key.pem"

# ── 4. Certificate Signing Request ───────────────────────────────────────────
echo "[4] Creating CSR …"
openssl req -new \
  -key  "$OUTDIR/recipient-key.pem" \
  -out  "$OUTDIR/recipient-csr.pem" \
  -subj "/CN=bob.example/O=Example/C=US"

# ── 5. X.509 extension config ────────────────────────────────────────────────
# keyAgreement is the correct Key Usage for an EC key used in ECDH-ES.
EXT_CNF=$(mktemp /tmp/ec-ext-XXXXXX.cnf)
trap 'rm -f "$EXT_CNF"' EXIT

cat > "$EXT_CNF" <<'EOF'
[ext]
keyUsage         = critical, keyAgreement
extendedKeyUsage = clientAuth
subjectAltName   = DNS:bob.example
EOF

# ── 6. Sign CSR with RSA CA ───────────────────────────────────────────────────
echo "[5] Signing CSR with RSA CA (1 year) …"
openssl x509 -req \
  -in           "$OUTDIR/recipient-csr.pem" \
  -CA           "$OUTDIR/ca-cert.pem" \
  -CAkey        "$OUTDIR/ca-key.pem" \
  -CAcreateserial \
  -out          "$OUTDIR/recipient-cert.pem" \
  -days         365 \
  -extfile      "$EXT_CNF" \
  -extensions   ext

# ── 7. Extract EC public key from the signed certificate ─────────────────────
echo "[6] Extracting EC public key from certificate …"
openssl x509 \
  -in      "$OUTDIR/recipient-cert.pem" \
  -pubkey  -noout \
  -out     "$OUTDIR/recipient-pub.pem"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "Done. Files in: $OUTDIR"
printf "  %-22s %s\n" "ca-key.pem"         "RSA-4096 CA private key          (KEEP SECRET)"
printf "  %-22s %s\n" "ca-cert.pem"        "RSA CA self-signed certificate   (share freely)"
printf "  %-22s %s\n" "recipient-key.pem"  "Bob's EC P-256 private key       (KEEP SECRET)"
printf "  %-22s %s\n" "recipient-csr.pem"  "Bob's certificate signing request"
printf "  %-22s %s\n" "recipient-cert.pem" "Bob's EC cert, signed by RSA CA"
printf "  %-22s %s\n" "recipient-pub.pem"  "Bob's EC public key (extracted from cert)"
echo ""
echo "Verify certificate signature:"
echo "  openssl verify -CAfile $OUTDIR/ca-cert.pem $OUTDIR/recipient-cert.pem"
