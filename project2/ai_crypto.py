"""AES-256-GCM file encryption/decryption with a passphrase.

File layout written by encrypt_file:
    salt (16 bytes) | nonce (12 bytes) | ciphertext + GCM tag (16 bytes)
"""
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_LEN = 16
NONCE_LEN = 12
ITERATIONS = 600_000  # PBKDF2 work factor (OWASP guidance for SHA-256)


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = AES-256
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(passphrase.encode())


def encrypt_file(in_path: str, out_path: str, passphrase: str) -> None:
    """Encrypt in_path to out_path using AES-256-GCM."""
    salt = os.urandom(SALT_LEN)    # fresh random salt every time
    nonce = os.urandom(NONCE_LEN)  # fresh random nonce every time (never reuse with a key)
    key = _derive_key(passphrase, salt)

    with open(in_path, "rb") as f:
        plaintext = f.read()

    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)  # tag appended

    with open(out_path, "wb") as f:
        f.write(salt + nonce + ciphertext)


def decrypt_file(in_path: str, out_path: str, passphrase: str) -> None:
    """Decrypt a file made by encrypt_file. Raises InvalidTag on wrong
    passphrase or if the file was modified."""
    with open(in_path, "rb") as f:
        data = f.read()

    salt = data[:SALT_LEN]
    nonce = data[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = data[SALT_LEN + NONCE_LEN:]

    key = _derive_key(passphrase, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)

    with open(out_path, "wb") as f:
        f.write(plaintext)


if __name__ == "__main__":
    import getpass
    import sys

    if len(sys.argv) != 4 or sys.argv[1] not in ("enc", "dec"):
        sys.exit("usage: python aes_file.py enc|dec <input> <output>")

    mode, src, dst = sys.argv[1:]
    pw = getpass.getpass("Passphrase: ")
    (encrypt_file if mode == "enc" else decrypt_file)(src, dst, pw)
