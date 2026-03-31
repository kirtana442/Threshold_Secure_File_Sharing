"""
decrypt.py — CLI entry point for Phase 2 of the Threshold-Based Secure File Sharing System.

Usage:
    python decrypt.py <output_folder> <share1> <share2>

Example:
    python decrypt.py ./output ./output/share_1.bin ./output/share_2.bin

Reads:
    encrypted_file.bin
    metadata.json
    share files

Writes:
    decrypted_file.bin
"""

import argparse
import sys
from pathlib import Path

import crypto_utils


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        argparse.Namespace containing:
            output_folder: directory containing encrypted artefacts
            share1: first share file
            share2: second share file
    """
    parser = argparse.ArgumentParser(
        prog="decrypt.py",
        description="Phase 2 — Threshold Secure File Sharing Decryption",
    )

    parser.add_argument(
        "output_folder",
        type=Path,
        help="Directory containing encrypted artefacts",
    )

    parser.add_argument(
        "share1",
        type=Path,
        help="First share file",
    )

    parser.add_argument(
        "share2",
        type=Path,
        help="Second share file",
    )

    return parser.parse_args()


def validate_inputs(
    output_folder: Path,
    share1: Path,
    share2: Path,
) -> None:
    """
    Validate input paths.

    Args:
        output_folder: directory containing encrypted data
        share1: first share file
        share2: second share file

    Raises:
        SystemExit if validation fails
    """
    if not output_folder.exists():
        _fatal(f"Output folder not found: {output_folder}")

    if not output_folder.is_dir():
        _fatal(f"Output folder is not directory: {output_folder}")

    for share in [share1, share2]:
        if not share.exists():
            _fatal(f"Share file not found: {share}")
        if not share.is_file():
            _fatal(f"Share path is not file: {share}")


def run_decryption(
    output_folder: Path,
    share1: Path,
    share2: Path,
) -> None:
    """
    Run full decryption pipeline with signature verification.
    """

    encrypted_file = output_folder / "encrypted_file.bin"
    metadata_file = output_folder / "metadata.json"
    signature_file = output_folder / "signature.bin"
    public_key_file = output_folder / "public_key.pem"

    if not encrypted_file.exists():
        _fatal("encrypted_file.bin not found")

    if not metadata_file.exists():
        _fatal("metadata.json not found")

    if not signature_file.exists():
        _fatal("signature.bin not found")

    if not public_key_file.exists():
        _fatal("public_key.pem not found")

    try:
        ciphertext = encrypted_file.read_bytes()
    except OSError as exc:
        _fatal(f"Failed to read ciphertext: {exc}")

    try:
        metadata_bytes = crypto_utils.load_metadata_bytes(metadata_file)
        metadata = crypto_utils.load_metadata(metadata_file)
        
    except Exception as exc:
        _fatal(f"Metadata load failed: {exc}")

    print("[*] Loading signature")
    signature = crypto_utils.load_signature(signature_file)

    print("[*] Loading public key")
    public_key = crypto_utils.load_public_key(public_key_file)

    print("[*] Verifying signature")
    payload_hash = crypto_utils.hash_encrypted_payload(
        ciphertext,
        metadata_bytes,
    )

    try:
        crypto_utils.verify_signature(
            public_key,
            signature,
            payload_hash,
        )
    except Exception:
        _fatal("Signature verification failed")

    print("[*] Signature verified")

    try:
        share_a = crypto_utils.load_share(share1)
        share_b = crypto_utils.load_share(share2)
    except Exception as exc:
        _fatal(f"Share loading failed: {exc}")

    try:
        master_key = crypto_utils.combine_shares(
            [share_a, share_b]
        )
    except Exception as exc:
        _fatal(f"Share reconstruction failed: {exc}")

    try:
        aes_key = crypto_utils.derive_aes_key(master_key)
    except Exception as exc:
        _fatal(f"Key derivation failed: {exc}")

    try:
        plaintext = crypto_utils.decrypt_file(
            ciphertext,
            aes_key,
            metadata["nonce"],
        )
    except Exception as exc:
        _fatal(f"Decryption failed: {exc}")
    finally:
        aes_key = b"\x00" * len(aes_key)
        master_key = b"\x00" * len(master_key)

    output_file = output_folder / "decrypted_file.bin"

    try:
        output_file.write_bytes(plaintext)
    except OSError as exc:
        _fatal(f"Failed to write output: {exc}")

    print("Decryption complete")
    print(f"Output file: {output_file.resolve()}")

def _fatal(message: str) -> None:
    """
    Print error and exit.

    Args:
        message: error message
    """
    print(f"[ERROR] {message}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    """
    Main entry point.
    """
    args = parse_args()
    validate_inputs(
        args.output_folder,
        args.share1,
        args.share2,
    )

    run_decryption(
        args.output_folder,
        args.share1,
        args.share2,
    )


if __name__ == "__main__":
    main()