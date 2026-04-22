# End-to-end JWE (encrypted JWT) tutorial — EC P-256 + AES-128-GCM (128-bit security tier)

A small, heavily-commented Python program that shows how to send a
**confidential** JWT from Alice to Bob using **JWE** (JSON Web Encryption)
with strong, modern elliptic-curve crypto.

The token carries custom attributes — `name`, `email`, `phone` — alongside
the standard JWT claims (`iss`, `sub`, `aud`, `iat`, `exp`). Every step is
printed with a banner so you can follow exactly what happens.

## Why JWE and not just JWS?

| Goal                     | JWS (signed JWT) | JWE (encrypted JWT) |
|--------------------------|:----------------:|:-------------------:|
| Integrity / authenticity |        ✅        |         ✅          |
| **Confidentiality**      |        ❌        |         ✅          |

A JWS is base64url — *anyone* who sees the token can read the claims.
If your claims contain PII (name, email, phone) you need JWE.

## Crypto choices — 128-bit security tier

Everything below is matched so the **whole chain** sits at the 128-bit
security level. Weakening any one link (e.g. mixing AES-128 with a P-521
key) would just waste cycles without buying extra security.

| Piece                   | Choice                  | Why                                                                              |
|-------------------------|-------------------------|----------------------------------------------------------------------------------|
| Recipient key pair      | **EC P-256** (`prime256v1` / `secp256r1`) | The EC curve that provides ≈128-bit security — matches AES-128.       |
| Key management (`alg`)  | **ECDH-ES** (Direct Key Agreement) | Ephemeral-static ECDH → shared secret used **directly** as the Content Encryption Key (no key-wrap step, so the `encrypted_key` segment is empty). Gives **perfect forward secrecy** per message. |
| Content encryption (`enc`) | **A128GCM**          | AES-128 in GCM — authenticated encryption, one primitive for confidentiality + integrity. |
| Serialization           | JWE **Compact**         | 5 dot-separated base64url segments, URL-safe.                                   |

The resulting token looks like:

```
BASE64URL(header) . BASE64URL(encrypted_key) . BASE64URL(iv)
                  . BASE64URL(ciphertext)    . BASE64URL(tag)
```

With `alg=ECDH-ES` (direct), the `encrypted_key` segment is empty — the
token still has 5 dot-separated parts, but the second one is a zero-length
string (`..`).

## Files

```
.
├── README.md              ← you are here
├── recipient-key.pem      ← Bob's EC P-256 private key  (KEEP SECRET)
├── recipient-pub.pem      ← Bob's EC P-256 public key   (share freely)
├── requirements.txt
└── jwe_example.py         ← the tutorial program
```

## 1. Generate the recipient key pair with OpenSSL

Bob generates a P-256 EC key pair once and publishes only the public half.
`prime256v1` is OpenSSL's name for NIST P-256 / secp256r1 — they're the
same curve — and it sits at the 128-bit security level.

```bash
# Private key (PEM, traditional EC format)
openssl ecparam -name prime256v1 -genkey -noout -out recipient-key.pem

# Public key derived from the private key
openssl ec -in recipient-key.pem -pubout -out recipient-pub.pem

# Protect the private key file
chmod 600 recipient-key.pem
```

Verify the curve:

```bash
openssl pkey -in recipient-key.pem -text -noout | tail -2
# ASN1 OID: prime256v1
# NIST CURVE: P-256
```

> In production, the **sender** only ever holds `recipient-pub.pem`. The
> private key never leaves Bob's machine / HSM / KMS. This tutorial loads
> both so one script can demo both sides.

## 2. Install and run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python jwe_example.py
```

## 3. What the program does, step by step

1. **Load** Bob's private and public keys from the PEM files, convert them
   to JWK so we can see the raw `x`, `y`, `d` parameters.
2. **Build** the JWT claim set (standard + `name`, `email`, `phone`).
3. **Choose** the JWE protected header: `alg=ECDH-ES`, `enc=A128GCM`,
   `typ=JWT`, plus a `kid` so Bob knows which key to use.
4. **Encrypt**. Under the hood jwcrypto:
   1. generates a fresh ephemeral EC P-256 key pair,
   2. runs ECDH with Bob's public key → shared secret `Z`,
   3. derives a 128-bit Content Encryption Key directly via Concat-KDF
      (SHA-256) — RFC 7518 §4.6. No separate key-wrap step.
   4. AES-128-GCM encrypts `JSON(claims)` under the CEK,
   5. emits the 5-part compact JWE (with an empty `encrypted_key`
      segment, since the CEK was derived, not wrapped).
5. **Peek** at the protected header without decrypting — this is how a
   recipient picks the right private key (`kid`).
6. **Decrypt** with Bob's private key, pinning the accepted algorithms
   (`algs=[...]`) to block alg-confusion downgrade attacks.
7. **Round-trip assert**: recovered claims must equal the originals.
8. **Tamper test**: flip a single byte of the ciphertext and confirm
   AES-GCM's auth tag rejects the forgery.

## 4. Security notes (read before reusing in prod)

- **Pin algorithms.** Always pass `algs=[...]` to the decrypt call. Never
  trust the `alg` in the header on its own.
- **Confidential ≠ authentic sender.** JWE proves the payload came from
  *someone who knew the public key* — not from Alice specifically. If
  you need sender authentication, use **nested JWT**: sign (JWS) first,
  then encrypt the JWS as the JWE payload (`cty=JWT`). Two key pairs,
  one for signing, one for encryption.
- **Forward secrecy only covers the recipient's long-term key.** The
  ephemeral key lives in memory for the duration of encryption; if that
  process is compromised *at encryption time*, the message is exposed.
- **Validate claims.** `exp`, `iat`, `iss`, `aud`, `sub` are application
  policy — check them after decryption. This tutorial does not, to keep
  the focus on the cryptography.
- **Key storage.** Put `recipient-key.pem` in a KMS/HSM/SOPS-encrypted
  store for anything beyond a tutorial. Never commit it to git.

## 5. Sample output (excerpt)

```
[4] JWE protected header (will travel in clear, b64url-encoded):
{
  "alg": "ECDH-ES",
  "enc": "A128GCM",
  "kid": "bob-ec-p256-2026",
  "typ": "JWT"
}

[5] JWE compact serialization (what you'd send over the wire):
eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIs...

[8] Decrypted claims (match the original exactly):
{
  "aud":   "https://bob.example/",
  "email": "ada@example.org",
  "name":  "Ada Lovelace",
  "phone": "+44 20 7946 0958",
  ...
}

[10a] As expected, decryption rejected the tampered token:
      InvalidJWEData: No recipient matched the provided key ['Failed: [InvalidTag()]']
```

## 6. Appendix: keys, certificates, and key usage

Background concepts that sit underneath the JWE choices above.

### Keys vs certificates

A cryptographic **key pair** consists of:

- **Private key** — kept secret; used for signing, decryption (RSA),
  or key agreement (EC).
- **Public key** — shared; used for signature verification, encryption
  (RSA), or key agreement (EC).

A **certificate** (X.509) is a *container for a public key plus
metadata*, signed by a CA (or self-signed). It includes:

- Subject (identity)
- Public key
- Validity period
- Issuer
- Key Usage constraints

A certificate does **not** add cryptographic capability — it only
describes and constrains how the key should be used.

### Key Usage (X.509)

Key Usage declares the allowed operations for a key.

| Key Usage         | Meaning                                  |
|-------------------|------------------------------------------|
| `digitalSignature`| Signing (JWT, TLS auth)                  |
| `keyEncipherment` | Encrypting keys (RSA)                    |
| `keyAgreement`    | Deriving shared secrets (EC / DH)        |
| `dataEncipherment`| Encrypting raw data (rare)               |

Key Usage is a **policy constraint**, not a cryptographic one — the
maths doesn't stop you using the key another way. Enforcement comes
from TLS stacks, HSMs, and enterprise PKI.

### RSA vs EC

- **RSA** supports both signatures and encryption directly.
- **EC** (Elliptic Curve) supports signatures (ECDSA / EdDSA) and
  **key agreement** (ECDH); there is no direct "encrypt with EC public
  key" primitive. JWE handles this by using ECDH to derive a symmetric
  key that then encrypts the payload — which is exactly what
  `alg=ECDH-ES` does in this tutorial.

## 7. Further reading

- RFC 7516 — JSON Web Encryption (JWE)
- RFC 7518 — JSON Web Algorithms (JWA), esp. §4.6 (ECDH-ES) and §5.3 (A*GCM)
- RFC 7519 — JSON Web Token (JWT)
- RFC 8037 — CFRG curves (if you later want X25519/Ed25519)
