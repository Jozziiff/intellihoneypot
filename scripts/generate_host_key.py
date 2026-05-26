#!/usr/bin/env python3
"""
Generate an RSA host key for the SSH honeypot.
Writes keys/host_rsa (private) and keys/host_rsa.pub (public).
Safe to re-run — will not overwrite an existing key.
"""
from __future__ import annotations

import sys
from pathlib import Path

import paramiko

KEYS_DIR = Path(__file__).parent.parent / "keys"
KEY_PATH = KEYS_DIR / "host_rsa"
PUB_PATH = KEYS_DIR / "host_rsa.pub"


def generate() -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if KEY_PATH.exists():
        print(f"Host key already exists at {KEY_PATH} — skipping.")
        return

    print("Generating 2048-bit RSA host key...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(KEY_PATH))

    with open(PUB_PATH, "w") as f:
        f.write(f"{key.get_name()} {key.get_base64()} honeypot@ubuntu-server\n")

    print(f"  Private key: {KEY_PATH}")
    print(f"  Public key:  {PUB_PATH}")
    print("Done.")


if __name__ == "__main__":
    generate()
