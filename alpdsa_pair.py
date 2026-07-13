#!/usr/bin/env python3
"""
alpdsa-pair — Pairing tool for AlpDSA.
Fetches the public key from an Android phone and stores it locally.
"""

import argparse
import os
import socket
import struct
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

DEFAULT_PORT = 7654
DEFAULT_KEY_NAME = "phone"
CMD_GET_PUBKEY = 0x01


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from socket, accumulating chunks."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                f"Connection closed, received {len(buf)} of {n} bytes"
            )
        buf += chunk
    return buf


def fetch_public_key(host: str, port: int) -> bytes:
    """Connect to phone and request its active public key via GET_PUBKEY."""
    sock = socket.create_connection((host, port), timeout=3)
    try:
        sock.sendall(bytes([CMD_GET_PUBKEY]))
        len_bytes = recv_exact(sock, 4)
        pubkey_len = struct.unpack(">i", len_bytes)[0]
        if pubkey_len == -1:
            raise RuntimeError(
                "Phone refused: setup mode may be off or no active key selected"
            )
        return recv_exact(sock, pubkey_len)
    finally:
        sock.close()


def get_target_dir() -> str:
    """Return /etc/alpdsa if writable, else current directory."""
    if os.access("/etc", os.W_OK):
        return "/etc/alpdsa"
    print("WARNING: /etc not writable, using current directory.")
    return os.getcwd()


def main() -> None:
    """Parse args, fetch key, validate, save."""
    parser = argparse.ArgumentParser(description="AlpDSA pairing tool")
    parser.add_argument("--host", required=True, help="Phone IP address")
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help="TCP port (default: 7654)"
    )
    parser.add_argument(
        "--key-name", default=DEFAULT_KEY_NAME, help="Key identifier (default: phone)"
    )
    parser.add_argument(
        "--force", action="store_true", help="Overwrite existing key without asking"
    )
    args = parser.parse_args()

    print(f"Fetching public key from {args.host}:{args.port}...")
    try:
        pubkey_der = fetch_public_key(args.host, args.port)
    except (OSError, ConnectionError, RuntimeError, struct.error) as e:
        if isinstance(e, ConnectionRefusedError) or "Connection refused" in str(e):
            print("ERROR: Connection refused. Is the phone on the same Wi-Fi? Is Setup Mode enabled in AlpDSA? Is the server mode up?", file=sys.stderr)
        else:
            print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate key
    try:
        pub_key = load_der_public_key(pubkey_der)
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            raise ValueError("Not an EC key")
        if pub_key.curve.name != "secp256r1":
            raise ValueError(f"Expected secp256r1, got {pub_key.curve.name}")
    except (ValueError, TypeError) as e:
        print(f"ERROR: Invalid public key received: {e}", file=sys.stderr)
        sys.exit(1)

    target_dir = get_target_dir()
    os.makedirs(target_dir, exist_ok=True)

    # Save public key
    pubkey_path = os.path.join(target_dir, f"{args.key_name}.pub")
    if os.path.exists(pubkey_path) and not args.force:
        ans = input(f"Key {pubkey_path} already exists. Overwrite? [y/N] ")
        if ans.lower() != "y":
            print("Aborted.")
            sys.exit(0)

    with open(pubkey_path, "wb") as f:
        f.write(pubkey_der)
    print(f"OK. Public key saved to {pubkey_path}")

    # Append host/port to config (don't overwrite other keys)
    config_path = os.path.join(target_dir, "alpdsa.config")
    config_entry = f"{args.key_name} {args.host}:{args.port}\n"

    existing = set()
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            for line in f:
                existing.add(line.split()[0] if line.strip() else "")

    if args.key_name in existing and not args.force:
        print(
            f"Config entry for '{args.key_name}' already exists. Use --force to update."
        )
    else:
        # Remove old entry for this key if updating
        lines = []
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                lines = [line for line in f if not line.startswith(args.key_name + " ")]
        lines.append(config_entry)
        with open(config_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        print(f"Config updated in {config_path}")

    if target_dir != "/etc/alpdsa":
        print(f"\nINFO: Move these files to /etc/alpdsa/ for PAM to find them:")
        print(f"  sudo mkdir -p /etc/alpdsa")
        print(f"  sudo cp {args.key_name}.pub alpdsa.config /etc/alpdsa/")

if __name__ == "__main__":
    main()
