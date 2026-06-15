"""Cryptographic helpers (hashing, sealing)."""

import hashlib


def sha256_hex(data: bytes) -> str:
    """Return SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()
