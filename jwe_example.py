"""
Minimal end-to-end JWE tutorial.

Flow:  load recipient key  →  encrypt JWT  →  show as URL  →  decrypt.

Crypto (128-bit security tier):
    EC P-256  +  ECDH-ES  +  A128GCM

ECDH-ES (Direct Key Agreement): the shared secret derived via ECDH is used
directly as the Content Encryption Key — no separate key-wrap step, so the
JWE's "encrypted_key" segment is empty.

Key source (checked in order):
    1. recipient-cert.pem  — CA-signed X.509 certificate; the EC public key
                             is extracted from it at runtime.
    2. recipient-pub.pem   — bare EC public key (fallback).
Run setup_keys.sh first to generate both.
"""

import json
from pathlib import Path
from urllib.parse import quote

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jwcrypto import jwk, jwt


HERE = Path(__file__).resolve().parent


def banner(title: str) -> None:
    print(f"\n─── {title} " + "─" * (68 - len(title)))


# 1. Load Bob's key pair.
#    Public key preference: extract from the CA-signed certificate when present,
#    fall back to the bare public-key PEM otherwise.
banner("1. load keys")

cert_path = HERE / "recipient-cert.pem"
pub_path  = HERE / "recipient-pub.pem"
priv_path = HERE / "recipient-key.pem"

if cert_path.exists():
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    pub_pem = cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    recipient_pub = jwk.JWK.from_pem(pub_pem)
    print(f"public key source : {cert_path.name}  (EC key extracted from CA-signed cert)")
    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()
    print(f"cert subject      : {subject}")
    print(f"cert issuer       : {issuer}")
else:
    recipient_pub = jwk.JWK.from_pem(pub_path.read_bytes())
    print(f"public key source : {pub_path.name}  (bare public key)")

recipient_priv = jwk.JWK.from_pem(priv_path.read_bytes())
print(f"curve             : {recipient_pub['crv']}   (P-256 → 128-bit security)")

# 2. Build the claims.
banner("2. claims to encrypt")
claims = {
    "iss": "https://alice.example/",
    "name":  "Ada Lovelace",
    "email": "ada@example.org",
    "phone": "+44 20 7946 0958",
}
print(json.dumps(claims, indent=2))

# 3. Encrypt: ECDH-ES key management, A128GCM content encryption.
banner("3. encrypt → JWE compact")
token = jwt.JWT(
    header={"alg": "ECDH-ES", "enc": "A128GCM", "typ": "JWT"},
    claims=claims,
)
token.make_encrypted_token(recipient_pub)
compact = token.serialize()
print(compact)
print(f"\nlength = {len(compact)} characters")

# 4. Show the JWE inside a URL. Compact form is already base64url so the
#    only character that needs percent-encoding in a query value is '='
#    (and there isn't one here, because b64url drops padding); we still
#    run it through quote() so the snippet is copy-paste safe.
banner("4. JWE as it would appear in a URL")
url = f"https://bob.example/callback?token={quote(compact, safe='')}"
print(url)

# 5. Decrypt with Bob's private key; pin accepted algs to block downgrade.
banner("5. decrypt")
received = jwt.JWT(
    key=recipient_priv,
    jwt=compact,
    algs=["ECDH-ES", "A128GCM"],
)
print(json.dumps(json.loads(received.claims), indent=2))
