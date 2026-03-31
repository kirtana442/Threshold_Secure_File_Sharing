# Threshold-Based Secure File Sharing

A cryptographically secure file sharing system that leverages **Threshold Secret Sharing**, **Authenticated Encryption**, and **Digital Signatures** to ensure confidentiality, integrity, and strictly controlled access to sensitive data.

The system encrypts a file, splits the encryption key into multiple shares using Shamir's Secret Sharing, and requires a pre-defined minimum number of shares to reconstruct the key and decrypt the file. All encrypted artifacts are digitally signed to prevent any form of tampering.



## Features
* **AES-256-GCM:** Authenticated encryption providing both confidentiality and data integrity.
* **Threshold Secret Sharing:** Configurable 2-of-3 (or $k$-of-$n$) key splitting.
* **Digital Signatures:** Ed25519-based tamper detection for all encrypted payloads.
* **Secure Key Derivation:** Utilizes HKDF for generating robust encryption keys.
* **Metadata Protection:** Ensures the integrity of file metadata.
* **CLI Workflow:** Streamlined command-line interface for encryption and decryption.
* **Memory Security:** Proactive cleanup of sensitive keys from memory.

---

## Security Design

The system implements a multi-layered cryptographic defense strategy:

### 1. Confidentiality
* Files are encrypted using **AES-256-GCM**.
* A unique, random **96-bit nonce** is generated for every encryption operation to prevent replay attacks and pattern matching.

### 2. Access Control
* The master encryption key is split using **Shamir’s Secret Sharing (SSS)**.
* A minimum **threshold** of shares is strictly required to reconstruct the key.
    > **Example:** If 3 shares are generated with a threshold of 2, any 1 share alone is mathematically useless; exactly 2 shares must be provided to recover the file.

### 3. Integrity and Authenticity
* The encrypted payload is hashed using **SHA-256**.
* The resulting hash is signed using an **Ed25519 private key**.
* **Verification:** The signature is verified against the public key before any decryption logic begins. This effectively prevents:
    * File tampering or bit-flipping.
    * Metadata modification.
    * Share substitution attacks.

---

## Cryptographic Components

| Component | Algorithm |
| :--- | :--- |
| **Encryption** | AES-256-GCM |
| **Key Splitting** | Shamir’s Secret Sharing |
| **Signature** | Ed25519 |
| **Hashing** | SHA-256 |
| **Key Derivation** | HKDF |

---

## Installation

**Requirement:** Python 3.9 or newer is recommended.

1.  **Clone the repository** (or navigate to the project folder).
2.  **Install dependencies:**

```bash
pip install cryptography secretsharing
```
*Alternatively, if using the requirements file:*
```bash
pip install -r requirements.txt
```

---

## Usage

### Encryption
Encrypt a file and generate the threshold shares:

```bash
python threshold_share/encrypt.py secret.txt output
```
**Generated Artifacts:** `encrypted_file.bin`, `metadata.json`, `signature.bin`, `public_key.pem`, and `share_N.bin`.

### Decryption
Reconstruct the master key using the required threshold of shares:

```bash
python threshold_share/decrypt.py output output/share_1.bin output/share_2.bin
```
**Result:** `decrypted_file.bin`

---

## Workflows

### Encryption Workflow
1.  Generate a random **Master Key**.
2.  Derive the **AES Key** via HKDF.
3.  Encrypt the file using **AES-GCM**.
4.  Split the Master Key into $N$ shares.
5.  Generate an **Ed25519** signature key pair.
6.  Hash the encrypted payload and sign it.
7.  Persist all artifacts to the output directory.

### Decryption Workflow
1.  Load the encrypted file and metadata.
2.  **Verify the digital signature** (Abort if failed).
3.  Load the provided threshold shares.
4.  Reconstruct the **Master Key**.
5.  Derive the **AES Key**.
6.  Decrypt the file and write the output.

---

## Threat Model

| This system PROTECTS against: | This system is NOT designed for: |
| :--- | :--- |
| Unauthorized file access | Compromised endpoints (Keyloggers/Rootkits) |
| File tampering | Malicious key holders (collusion) |
| Share theft (below threshold) | Side-channel attacks on hardware |
| Metadata manipulation | |

