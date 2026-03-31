"""
crypto_utils.py — Core cryptographic utilities for the Threshold-Based Secure File Sharing System.

Implements:
  - Master key generation (os.urandom)
  - AES-256 key derivation via HKDF-SHA256
  - File encryption using AES-256-GCM
  - 2-of-3 Shamir Secret Sharing key splitting
  - Secure share and metadata persistence
"""

import base64
import json
import os
from pathlib import Path
from typing import List, Tuple, Dict

from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

MASTER_KEY_LENGTH: int = 16        # bytes — input to HKDF
AES_KEY_LENGTH: int = 32           # bytes — AES-256
NONCE_LENGTH: int = 12             # bytes — recommended for AES-GCM
KDF_ALGORITHM: str = "HKDF-SHA256"
KDF_INFO: bytes = b"threshold-file-sharing"
METADATA_VERSION: int = 1
SHAMIR_THRESHOLD: int = 2
SHAMIR_TOTAL_SHARES: int = 3



def generate_master_key() -> bytes:
    """
    Generate a cryptographically secure random master key.

    Uses os.urandom which pulls from the OS entropy pool (e.g., /dev/urandom
    on Linux), suitable for cryptographic use.

    Returns:
        bytes: 16-byte random master key.
    """
    return os.urandom(MASTER_KEY_LENGTH)



def derive_aes_key(master_key: bytes) -> bytes:
    """
    Derive a 256-bit AES key from the master key using HKDF-SHA256.

    HKDF (RFC 5869) provides domain separation via the `info` parameter,
    preventing key reuse across different contexts even with the same
    master key material.

    Args:
        master_key: Raw input key material (16 bytes).

    Returns:
        bytes: 32-byte derived AES-256 key.

    Raises:
        ValueError: If master_key is empty or not bytes.
    """
    if not isinstance(master_key, bytes) or len(master_key) == 0:
        raise ValueError("master_key must be a non-empty bytes object.")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LENGTH,
        salt=None,       # No salt: HKDF uses a zero-filled salt of hash length
        info=KDF_INFO,
    )
    return hkdf.derive(master_key)



def encrypt_file(plaintext: bytes, aes_key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM with a randomly generated nonce.

    AES-GCM provides both confidentiality and integrity (authenticated
    encryption). The 12-byte nonce is the NIST-recommended size for GCM,
    allowing 2^32 invocations before nonce-space exhaustion.

    Args:
        plaintext: Raw file bytes to encrypt.
        aes_key:   32-byte AES-256 key.

    Returns:
        Tuple of (ciphertext_with_tag, nonce).
        - ciphertext_with_tag: Encrypted bytes with 16-byte GCM auth tag appended.
        - nonce: 12-byte random nonce used during encryption.

    Raises:
        ValueError: If aes_key is not exactly 32 bytes.
    """
    if len(aes_key) != AES_KEY_LENGTH:
        raise ValueError(f"AES key must be {AES_KEY_LENGTH} bytes; got {len(aes_key)}.")

    nonce = os.urandom(NONCE_LENGTH)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return ciphertext, nonce



def split_key(master_key: bytes) -> List[Tuple[int, bytes]]:
    """
    Split the master key into 3 shares using 2-of-3 Shamir Secret Sharing.

    Shamir's scheme (GF(2^8) field, as implemented by PyCryptodome) ensures
    that any 2 shares are sufficient to reconstruct the secret, while a
    single share reveals nothing about the secret.

    Note: PyCryptodome's Shamir.split requires the secret to be exactly
    16 bytes, matching our MASTER_KEY_LENGTH.

    Args:
        master_key: 16-byte master key to split.

    Returns:
        List of (index, share_bytes) tuples, one per share.

    Raises:
        ValueError: If master_key is not exactly 16 bytes.
    """
    if len(master_key) != MASTER_KEY_LENGTH:
        raise ValueError(
            f"Shamir split requires exactly {MASTER_KEY_LENGTH} bytes; "
            f"got {len(master_key)}."
        )

    shares = Shamir.split(SHAMIR_THRESHOLD, SHAMIR_TOTAL_SHARES, master_key)
    return shares  # List of (int, bytes) tuples



def save_shares(shares: List[Tuple[int, bytes]], output_dir: Path) -> None:
    """
    Persist each Shamir share to a separate binary file.

    File format: 1 byte index (uint8) | N bytes share data.
    This allows the decryption phase to recover the share index
    without a separate index file.

    Args:
        shares:     List of (index, share_bytes) from split_key().
        output_dir: Directory where share files will be written.

    Raises:
        OSError: If the output directory cannot be written to.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    for idx, share_data in shares:
        share_path = output_dir / f"share_{idx}.bin"
        # Prepend the 1-byte index so the file is self-describing
        payload = bytes([idx]) + share_data
        share_path.write_bytes(payload)


def save_metadata(
    nonce: bytes,
    output_dir: Path,
) -> None:
    """
    Write encryption metadata to metadata.json in the output directory.

    All binary values are Base64-encoded (standard encoding, no line breaks)
    for safe JSON serialisation. The metadata file does NOT contain any
    key material — it is safe to store alongside the ciphertext.

    Schema:
        version   (int)  : Format version for forward-compatibility.
        algorithm (str)  : Symmetric cipher identifier.
        threshold (int)  : Minimum shares required for reconstruction.
        shares    (int)  : Total shares produced.
        nonce     (str)  : Base64-encoded 12-byte AES-GCM nonce.
        kdf       (str)  : Key derivation function identifier.
        info      (str)  : HKDF info parameter (plain text).

    Args:
        nonce:      12-byte AES-GCM nonce used during encryption.
        output_dir: Directory where metadata.json will be written.

    Raises:
        OSError: If the file cannot be written.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "version": METADATA_VERSION,
        "algorithm": "AES-256-GCM",
        "threshold": SHAMIR_THRESHOLD,
        "shares": SHAMIR_TOTAL_SHARES,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "kdf": KDF_ALGORITHM,
        "info": KDF_INFO.decode("ascii"),
    }

    metadata_path = output_dir / "metadata.json"
    metadata_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

def load_share(path: Path) -> Tuple[int, bytes]:
    """
    Load a Shamir share file.

    File format:
        1 byte index
        remaining bytes share data

    Args:
        path: path to share file

    Returns:
        Tuple containing index and share bytes

    Raises:
        ValueError if file invalid
    """
    data = path.read_bytes()

    if len(data) < 2:
        raise ValueError("Invalid share file")

    idx = data[0]
    share = data[1:]

    return idx, share


def combine_shares(
    shares: List[Tuple[int, bytes]]
) -> bytes:
    """
    Combine Shamir shares.

    Args:
        shares: list of share tuples

    Returns:
        reconstructed master key
    """
    if len(shares) < SHAMIR_THRESHOLD:
        raise ValueError("Insufficient shares")

    return Shamir.combine(shares)


def load_metadata(path: Path) -> Dict:
    """
    Load metadata.json.

    Args:
        path: metadata file path

    Returns:
        dictionary containing metadata
    """
    raw = path.read_text(encoding="utf-8")
    metadata = json.loads(raw)

    required = [
        "version",
        "algorithm",
        "threshold",
        "shares",
        "nonce",
        "kdf",
        "info",
    ]

    for field in required:
        if field not in metadata:
            raise ValueError(f"Missing metadata field: {field}")

    metadata["nonce"] = base64.b64decode(metadata["nonce"])

    return metadata


def decrypt_file(
    ciphertext: bytes,
    aes_key: bytes,
    nonce: bytes,
) -> bytes:
    """
    Decrypt AES-256-GCM ciphertext.

    Args:
        ciphertext: encrypted data
        aes_key: AES key
        nonce: AES nonce

    Returns:
        plaintext bytes
    """
    if len(aes_key) != AES_KEY_LENGTH:
        raise ValueError("Invalid AES key length")

    aesgcm = AESGCM(aes_key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        None,
    )

    return plaintext

def generate_signing_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """
    Generate an Ed25519 keypair for signing and verification.
    Returns private and public key.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def hash_encrypted_payload(ciphertext: bytes, metadata_bytes: bytes) -> bytes:
    """
    Compute SHA256 hash over ciphertext and metadata.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(ciphertext)
    digest.update(metadata_bytes)
    return digest.finalize()


def sign_payload(private_key: Ed25519PrivateKey, payload_hash: bytes) -> bytes:
    """
    Sign hashed payload using Ed25519 private key.
    """
    return private_key.sign(payload_hash)


def verify_signature(
    public_key: Ed25519PublicKey,
    signature: bytes,
    payload_hash: bytes,
) -> None:
    """
    Verify Ed25519 signature.
    Raises InvalidSignature if verification fails.
    """
    public_key.verify(signature, payload_hash)


def save_public_key(path: Path, public_key: Ed25519PublicKey) -> None:
    """
    Save public key in PEM format.
    """
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(path, "wb") as f:
        f.write(public_bytes)


def load_public_key(path: Path) -> Ed25519PublicKey:
    """
    Load public key from PEM file.
    """
    with open(path, "rb") as f:
        data = f.read()

    return serialization.load_pem_public_key(data)


def save_signature(path: Path, signature: bytes) -> None:
    """
    Save signature to file.
    """
    with open(path, "wb") as f:
        f.write(signature)


def load_signature(path: Path) -> bytes:
    """
    Load signature from file.
    """
    with open(path, "rb") as f:
        return f.read()
    
def serialize_metadata(metadata: dict) -> bytes:
    """
    Serialize metadata deterministically for signing.
    """
    import json

    return json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

def load_metadata_bytes(path: Path) -> bytes:
    """
    Load metadata JSON as deterministic bytes for signature verification.
    """
    import json

    with open(path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    return json.dumps(
        metadata,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()