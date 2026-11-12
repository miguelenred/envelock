#!/usr/bin/env python3
"""PUBLIC, deterministic test keys. NEVER use these identities to protect a product."""

import argparse
import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("envelock", ROOT / "encoder/envelock.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def get_material():
    seed = hashlib.sha256(b"Envelock PUBLIC DEMO signing seed v2").digest()
    signer = a.Ed25519PrivateKey.from_private_bytes(seed)
    owner = {
        "kind": "envelock-owner",
        "format": a.FORMAT_VERSION,
        "signing_private": seed.hex(),
        "signing_public": a.raw_public(signer.public_key()).hex(),
    }
    x_seed = hashlib.sha256(b"Envelock PUBLIC DEMO x25519 seed v2").digest()
    x = a.X25519PrivateKey.from_private_bytes(x_seed)
    recipient = {
        "kind": "envelock-recipient",
        "format": a.FORMAT_VERSION,
        "label": "PUBLIC-DEMO-DO-NOT-USE-IN-PRODUCTION",
        "x25519_private": a.raw_x_private(x).hex(),
        "x25519_public": a.raw_x_public(x.public_key()).hex(),
    }
    return owner, recipient


def fuzz_header(identity: dict) -> str:
    def arr(name, hx):
        data = bytes.fromhex(hx)
        return (
            f"static const unsigned char {name}[{len(data)}] = {{"
            + ",".join("0x%02x" % b for b in data)
            + "};\n"
        )

    return (
        "/* PUBLIC DEMO identity for fuzzing only. Reproducible from source. */\n"
        "#ifndef ENVELOCK_AUDIT_KEYS_H\n#define ENVELOCK_AUDIT_KEYS_H\n"
        + arr("envelock_x25519_private", identity["x25519_private"])
        + arr("envelock_x25519_public", identity["x25519_public"])
        + arr("envelock_signing_public", identity["signing_public"])
        + "#endif\n"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fuzz-header", type=Path, help="Also emit a C header for the fuzzer")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    owner, recipient = get_material()
    identity = a.make_identity(recipient, owner)
    a.save_json(args.output / "owner.json", owner)
    a.save_json(args.output / "recipient.json", recipient)
    a.secret_write(args.output / "identity.bin", a.identity_bytes(identity))
    (args.output / "DEMO_ONLY.txt").write_text(
        "PUBLIC TEST KEYS. They are reproducible from source. NOT suitable for software protection.\n"
    )
    if args.fuzz_header:
        a.secret_write(args.fuzz_header, fuzz_header(identity).encode())


if __name__ == "__main__":
    main()
