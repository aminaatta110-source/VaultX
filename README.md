# VaultX 🔐

A secure command-line password vault built with **AES-256-CBC** encryption and **PBKDF2-HMAC-SHA256** key derivation.

## How it works

```
Master Password → PBKDF2 (390,000 rounds + salt) → 256-bit key
                                                         ↓
                              Credential → AES-256-CBC (unique IV) → Encrypted blob
                                                         ↓
                                                    vault.json
```

- Your master password is **never stored** — only used to derive the encryption key
- Each credential is encrypted with a **fresh random IV**, so identical passwords never produce identical ciphertext  
- The vault file stores only the salt, IVs, and ciphertext — nothing recoverable without the master password

## Setup

```bash
pip install -r requirements.txt
python main.py
```

## Usage

```
╔══════════════════════════════╗
║   VaultX — Password Vault   ║
║   AES-256 · PBKDF2-SHA256   ║
╚══════════════════════════════╝

  [1] Add credential
  [2] Retrieve credential
  [3] List all sites
  [4] Delete credential
  [5] Exit
```

## Security design decisions

| Decision | Reason |
|---|---|
| PBKDF2 with 390,000 rounds | NIST SP 800-132 recommended minimum (2023) — slows brute-force |
| Random 256-bit salt | Ensures two users with the same master password get different keys |
| Unique IV per entry | Prevents ciphertext comparison attacks across entries |
| AES-256-CBC | Industry standard; 256-bit key space is computationally infeasible to brute-force |
| Master password via `getpass` | Never echoed to terminal or stored in shell history |

## Tech stack

- Python 3.10+
- [`cryptography`](https://cryptography.io) — AES-256, PBKDF2
