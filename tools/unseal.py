#!/usr/bin/env python3
"""Unseal a pipeline bundle (public runner repo tool).

Standalone on purpose: this file lives in the PUBLIC runner repo and must not
import anything from the sealed pipeline. It decrypts the CAPSEAL1 blob
produced by `scripts/seal_and_ship.py seal` using the X25519 private key in
the PIPELINE_SEAL_KEY secret.

Usage:
  python3 tools/unseal.py --in bundles/pipeline.seal --out /tmp/pipeline.tgz
"""

import argparse
import base64
import os
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC = b"CAPSEAL1"
_INFO = b"capseal-v1"


def open_bytes(blob: bytes, private_b64: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("not a CAPSEAL1 blob")
    priv = X25519PrivateKey.from_private_bytes(
        base64.urlsafe_b64decode(private_b64.encode()))
    recipient_pub = priv.public_key().public_bytes_raw()
    body = blob[len(MAGIC):]
    eph_pub, nonce, ct = body[:32], body[32:44], body[44:]
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = HKDF(algorithm=hashes.SHA256(), length=32,
               salt=eph_pub + recipient_pub, info=_INFO).derive(shared)
    return AESGCM(key).decrypt(nonce, ct, MAGIC)


def main() -> int:
    parser = argparse.ArgumentParser(description="Unseal a pipeline bundle")
    parser.add_argument("--in", dest="inp", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--key-env", default="PIPELINE_SEAL_KEY")
    args = parser.parse_args()

    key = os.environ.get(args.key_env, "")
    if not key:
        print(f"missing key env: {args.key_env}", file=sys.stderr)
        return 2
    with open(args.inp, "rb") as f:
        blob = f.read()
    data = open_bytes(blob, key.strip())
    with open(args.out, "wb") as f:
        f.write(data)
    print(f"unsealed {len(data)} bytes -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
