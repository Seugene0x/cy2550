"""fixed_crypto.py - AES-256-GCM file encryption with a passphrase (hardened).

File layout:
    magic "AESF" (4) | version (1) | PBKDF2 iterations (4, big-endian)
    | salt (16) | nonce (12) | ciphertext + GCM tag (16)

The whole header is passed to GCM as associated data, so any change to it
makes decryption fail.

Usage:
    python3 fixed_crypto.py enc <input> <output>
    python3 fixed_crypto.py dec <input> <output>
    python3 fixed_crypto.py selftest
"""
import getpass
import os
import struct
import sys
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"AESF"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + 1 + 4 + SALT_LEN + NONCE_LEN  # 37 bytes

ITERATIONS = 600_000                 # used for new files, stored in the header
MIN_ITER, MAX_ITER = 100_000, 5_000_000  # accepted range when reading a header
MIN_PASSPHRASE_LEN = 12
MAX_FILE_SIZE = 1024 ** 3            # 1 GiB: whole file is held in memory


class NotAnEncryptedFileError(ValueError):
    """Input is not a valid file produced by this program."""


class DecryptionError(Exception):
    """Authentication failed: wrong passphrase OR the file was modified."""


# ---------------------------------------------------------------- helpers
def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=iterations)
    return kdf.derive(passphrase.encode("utf-8"))


def _check_passphrase(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        raise ValueError(
            f"passphrase too short: use at least {MIN_PASSPHRASE_LEN} characters")


def _check_paths(in_path: str, out_path: str, overwrite: bool) -> None:
    if not os.path.isfile(in_path):
        raise FileNotFoundError(f"input file not found: {in_path}")
    if os.path.exists(out_path):
        if os.path.samefile(in_path, out_path):
            raise ValueError("input and output are the same file; refusing")
        if not overwrite:
            raise FileExistsError(
                f"{out_path} already exists (pass overwrite=True to replace it)")


def _read_input(in_path: str) -> bytes:
    if os.path.getsize(in_path) > MAX_FILE_SIZE:
        raise ValueError(f"file larger than {MAX_FILE_SIZE} bytes is not supported")
    with open(in_path, "rb") as f:
        return f.read()


def _write_private(path: str, data: bytes) -> None:
    """Write via a temp file in the same directory, then rename.

    mkstemp creates the file with mode 0600, so the output is never
    group/world readable, and a crash never leaves a half-written output.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


# ------------------------------------------------------------- public API
def encrypt_file(in_path: str, out_path: str, passphrase: str,
                 overwrite: bool = False) -> None:
    _check_passphrase(passphrase)
    _check_paths(in_path, out_path, overwrite)
    plaintext = _read_input(in_path)

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = (MAGIC + bytes([VERSION]) + struct.pack(">I", ITERATIONS)
              + salt + nonce)
    key = _derive_key(passphrase, salt, ITERATIONS)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)  # header = AAD
    _write_private(out_path, header + ciphertext)


def decrypt_file(in_path: str, out_path: str, passphrase: str,
                 overwrite: bool = False) -> None:
    _check_paths(in_path, out_path, overwrite)
    data = _read_input(in_path)

    # Format checks happen before any cryptography, with their own error.
    if len(data) < HEADER_LEN + TAG_LEN or not data.startswith(MAGIC):
        raise NotAnEncryptedFileError(
            "not a valid encrypted file (too short or wrong format)")
    if data[len(MAGIC)] != VERSION:
        raise NotAnEncryptedFileError("unsupported file version")
    (iterations,) = struct.unpack(">I", data[5:9])
    if not MIN_ITER <= iterations <= MAX_ITER:
        raise NotAnEncryptedFileError("corrupt header (bad iteration count)")

    header = data[:HEADER_LEN]
    salt = data[9:9 + SALT_LEN]
    nonce = data[9 + SALT_LEN:HEADER_LEN]
    ciphertext = data[HEADER_LEN:]

    key = _derive_key(passphrase, salt, iterations)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise DecryptionError(
            "decryption failed: wrong passphrase, or the file was "
            "corrupted/tampered with") from None
    _write_private(out_path, plaintext)  # only written after authentication


# -------------------------------------------------------------- self-test
def selftest() -> bool:
    ok = True

    def check(name, cond):
        nonlocal ok
        ok &= bool(cond)
        print(f"[{'PASS' if cond else 'FAIL'}] {name}")

    def raises(exc, fn):
        try:
            fn()
        except exc:
            return True
        except Exception:
            return False
        return False

    pw = "correct horse battery"
    with tempfile.TemporaryDirectory() as d:
        p = lambda n: os.path.join(d, n)
        original = os.urandom(1024 * 1024)
        open(p("plain.bin"), "wb").write(original)
        open(p("empty.bin"), "wb").write(b"")

        encrypt_file(p("plain.bin"), p("a.enc"), pw)
        encrypt_file(p("plain.bin"), p("b.enc"), pw)
        decrypt_file(p("a.enc"), p("out.bin"), pw)
        check("round trip: decrypted == original (1 MiB)",
              open(p("out.bin"), "rb").read() == original)

        encrypt_file(p("empty.bin"), p("e.enc"), pw)
        decrypt_file(p("e.enc"), p("e.out"), pw)
        check("round trip: empty file", open(p("e.out"), "rb").read() == b"")

        check("same file + same passphrase -> different ciphertext",
              open(p("a.enc"), "rb").read() != open(p("b.enc"), "rb").read())

        check("wrong passphrase -> DecryptionError, no output written",
              raises(DecryptionError,
                     lambda: decrypt_file(p("a.enc"), p("w.out"), "wrong passphrase!!"))
              and not os.path.exists(p("w.out")))

        blob = bytearray(open(p("a.enc"), "rb").read())
        blob[HEADER_LEN + 5] ^= 1
        open(p("t_ct.enc"), "wb").write(blob)
        check("tampered ciphertext -> DecryptionError",
              raises(DecryptionError,
                     lambda: decrypt_file(p("t_ct.enc"), p("t.out"), pw)))

        blob = bytearray(open(p("a.enc"), "rb").read())
        blob[10] ^= 1  # inside the salt
        open(p("t_hd.enc"), "wb").write(blob)
        check("tampered header -> DecryptionError",
              raises(DecryptionError,
                     lambda: decrypt_file(p("t_hd.enc"), p("t.out"), pw)))

        open(p("short.enc"), "wb").write(b"x" * 20)
        open(p("junk.enc"), "wb").write(os.urandom(200))
        check("truncated file -> NotAnEncryptedFileError (clear message)",
              raises(NotAnEncryptedFileError,
                     lambda: decrypt_file(p("short.enc"), p("s.out"), pw)))
        check("random junk -> NotAnEncryptedFileError",
              raises(NotAnEncryptedFileError,
                     lambda: decrypt_file(p("junk.enc"), p("s.out"), pw)))

        check("weak/empty passphrase refused",
              raises(ValueError, lambda: encrypt_file(p("plain.bin"), p("x.enc"), ""))
              and raises(ValueError, lambda: encrypt_file(p("plain.bin"), p("x.enc"), "pizza")))

        open(p("keep.txt"), "wb").write(b"precious")
        check("in == out refused, original intact",
              raises(ValueError, lambda: encrypt_file(p("keep.txt"), p("keep.txt"), pw))
              and open(p("keep.txt"), "rb").read() == b"precious")

        check("existing output not overwritten by default",
              raises(FileExistsError,
                     lambda: encrypt_file(p("plain.bin"), p("a.enc"), pw)))

        mode = os.stat(p("out.bin")).st_mode & 0o777
        check(f"decrypted file permissions are 0600 (got {oct(mode)})", mode == 0o600)
        mode = os.stat(p("a.enc")).st_mode & 0o777
        check(f"encrypted file permissions are 0600 (got {oct(mode)})", mode == 0o600)

        leftovers = [n for n in os.listdir(d) if n.startswith(".tmp-")]
        check("no temp files left behind after failures", not leftovers)

    print("ALL TESTS PASSED" if ok else "SOME TESTS FAILED")
    return ok


# -------------------------------------------------------------------- CLI
def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "selftest":
        return 0 if selftest() else 1
    if len(sys.argv) != 4 or sys.argv[1] not in ("enc", "dec"):
        print(__doc__)
        return 2
    mode, src, dst = sys.argv[1:]
    try:
        if mode == "enc":
            pw = getpass.getpass("Passphrase: ")
            if getpass.getpass("Confirm passphrase: ") != pw:
                print("error: passphrases do not match")
                return 1
            encrypt_file(src, dst, pw)
        else:
            decrypt_file(src, dst, getpass.getpass("Passphrase: "))
    except (ValueError, FileNotFoundError, FileExistsError,
            NotAnEncryptedFileError, DecryptionError) as e:
        print(f"error: {e}")
        return 1
    print("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
