"""
encrypt.py — CLI entry point for Phase 1 of the Threshold-Based Secure File Sharing System.

Usage:
    python encrypt.py <input_file> <output_folder>

Example:
    python encrypt.py secret.pdf ./output

Outputs written to <output_folder>/:
    encrypted_file.bin  — AES-256-GCM ciphertext + auth tag
    share_1.bin         — Shamir share 1 (index byte + share data)
    share_2.bin         — Shamir share 2
    share_3.bin         — Shamir share 3
    metadata.json       — Non-secret encryption parameters (nonce, KDF info, etc.)
"""

import argparse
import sys
from pathlib import Path

import crypto_utils

def parse_args() -> argparse.Namespace:
    """
    Parse and validate command-line arguments.

    Returns:
        argparse.Namespace with attributes:
            input_file  (Path): Path to the plaintext file to encrypt.
            output_dir  (Path): Directory where output artefacts are written.
    """
    parser = argparse.ArgumentParser(
        prog="encrypt.py",
        description=(
            "Phase 1 — Threshold Secure File Sharing: "
            "encrypt a file with AES-256-GCM and split the key via 2-of-3 Shamir SSS."
        ),
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Path to the plaintext input file.",
    )
    parser.add_argument(
        "output_folder",
        type=Path,
        help="Directory where encrypted output and key shares will be stored.",
    )
    return parser.parse_args()



def validate_inputs(input_file: Path, output_dir: Path) -> None:
    """
    Validate CLI inputs before any cryptographic operation begins.

    Fail-fast validation ensures no partial output is written due to a
    trivially avoidable error (missing file, non-file path, etc.).

    Args:
        input_file: Path supplied by the user for the source file.
        output_dir: Path supplied by the user for the output directory.

    Raises:
        SystemExit: On any validation failure, with a descriptive message.
    """
    if not input_file.exists():
        _fatal(f"Input file not found: {input_file}")
    if not input_file.is_file():
        _fatal(f"Input path is not a regular file: {input_file}")
    if input_file.stat().st_size == 0:
        _fatal(f"Input file is empty: {input_file}")
    if output_dir.exists() and not output_dir.is_dir():
        _fatal(f"Output path exists and is not a directory: {output_dir}")



def run_encryption(input_file: Path, output_dir: Path) -> None:
    """
    Orchestrate the full encryption pipeline with threshold sharing and signing.
    """

    print(f"[*] Reading input file: {input_file}")
    try:
        plaintext = input_file.read_bytes()
    except OSError as exc:
        _fatal(f"Failed to read input file: {exc}")

    print("[*] Generating 16-byte master key")
    master_key = crypto_utils.generate_master_key()

    print("[*] Deriving AES-256 key via HKDF-SHA256")
    try:
        aes_key = crypto_utils.derive_aes_key(master_key)
    except ValueError as exc:
        _fatal(f"Key derivation failed: {exc}")

    print("[*] Encrypting file with AES-256-GCM")
    try:
        ciphertext, nonce = crypto_utils.encrypt_file(plaintext, aes_key)
    except (ValueError, Exception) as exc:
        _fatal(f"Encryption failed: {exc}")
    finally:
        aes_key = b"\x00" * len(aes_key)

    output_dir.mkdir(parents=True, exist_ok=True)
    encrypted_path = output_dir / "encrypted_file.bin"

    try:
        encrypted_path.write_bytes(ciphertext)
    except OSError as exc:
        _fatal(f"Failed to write encrypted file: {exc}")

    print("[*] Splitting master key")
    try:
        shares = crypto_utils.split_key(master_key)
    except ValueError as exc:
        _fatal(f"Shamir split failed: {exc}")
    finally:
        master_key = b"\x00" * len(master_key)

    print("[*] Saving shares")
    crypto_utils.save_shares(shares, output_dir)

    print("[*] Saving metadata")
    metadata = crypto_utils.save_metadata(nonce, output_dir)

    print("[*] Generating signing keypair")
    private_key, public_key = crypto_utils.generate_signing_keypair()

    crypto_utils.save_metadata(nonce, output_dir)

    metadata_path = output_dir / "metadata.json"
    metadata_bytes = crypto_utils.load_metadata_bytes(metadata_path)

    print("[*] Hashing encrypted payload")
    payload_hash = crypto_utils.hash_encrypted_payload(
        ciphertext,
        metadata_bytes,
    )

    print("[*] Creating signature")
    signature = crypto_utils.sign_payload(
        private_key,
        payload_hash,
    )

    crypto_utils.save_signature(
        output_dir / "signature.bin",
        signature,
    )

    crypto_utils.save_public_key(
        output_dir / "public_key.pem",
        public_key,
    )

    private_key = None

    print("Encryption complete")
    print(f"Output directory: {output_dir.resolve()}")


def _fatal(message: str) -> None:
    """Print an error message to stderr and exit with code 1."""
    print(f"[ERROR] {message}", file=sys.stderr)
    sys.exit(1)



def main() -> None:
    """Main entry point: parse args, validate, then run encryption."""
    args = parse_args()
    validate_inputs(args.input_file, args.output_folder)
    run_encryption(args.input_file, args.output_folder)


if __name__ == "__main__":
    main()