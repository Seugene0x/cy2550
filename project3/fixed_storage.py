"""
CY2550 Project 3 — Secure Password Storage
===========================================
Implement hash_password() and verify_password() below.

Allowed libraries (both are installed on the grading server):
  - bcrypt          (import bcrypt)
  - argon2-cffi     (from argon2 import PasswordHasher)

Do NOT use MD5, SHA-1, SHA-256, or any other fast hash function.
That is exactly what you spent this project cracking.

Test your implementation locally before submitting:
  python3 fixed_storage.py
"""

# Uncomment whichever library you plan to use:
# import bcrypt
# from argon2 import PasswordHasher


def hash_password(password: str) -> str:
    """
    Return a secure hash of password suitable for storing in a database.

    Requirements:
      - The returned string must NOT be the plaintext password.
      - The returned string must be accepted by verify_password() to
        authenticate future logins.
      - Each call should produce a different output even for the same
        password (i.e., use a random salt — bcrypt and argon2 do this
        automatically).

    Args:
        password: the plaintext password to hash

    Returns:
        A string representation of the hash (safe to store in a database)
    """
    raise NotImplementedError("Implement hash_password()")


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Return True if password matches stored_hash, False otherwise.

    Args:
        password:    the plaintext password to check
        stored_hash: the value previously returned by hash_password()

    Returns:
        True if the password is correct, False if it is not
    """
    raise NotImplementedError("Implement verify_password()")


# =============================================================================
# Self-test — run this file directly to check your implementation locally
# =============================================================================

if __name__ == "__main__":
    test_password = "Hunter2!"
    wrong_password = "not_the_right_password"

    print("Testing hash_password() and verify_password()...")

    try:
        h = hash_password(test_password)
    except NotImplementedError:
        print("FAIL — hash_password() is not implemented yet.")
        raise SystemExit(1)
    except Exception as e:
        print(f"FAIL — hash_password() raised an exception: {e}")
        raise SystemExit(1)

    if not isinstance(h, str) or len(h) < 10:
        print(f"FAIL — hash_password() returned an unexpected value: {h!r}")
        raise SystemExit(1)

    if h == test_password:
        print("FAIL — hash_password() returned the plaintext password unchanged.")
        raise SystemExit(1)

    print(f"  hash_password() returned: {h[:30]}...")

    try:
        result_correct = verify_password(test_password, h)
    except NotImplementedError:
        print("FAIL — verify_password() is not implemented yet.")
        raise SystemExit(1)
    except Exception as e:
        print(f"FAIL — verify_password() raised an exception: {e}")
        raise SystemExit(1)

    if result_correct is not True:
        print(f"FAIL — verify_password(correct_password, hash) returned {result_correct!r}; expected True.")
        raise SystemExit(1)

    print("  verify_password(correct_password, hash) → True  ✓")

    result_wrong = verify_password(wrong_password, h)
    if result_wrong is not False:
        print(f"FAIL — verify_password(wrong_password, hash) returned {result_wrong!r}; expected False.")
        raise SystemExit(1)

    print("  verify_password(wrong_password,  hash) → False ✓")

    # Verify that two hashes of the same password are different (salting)
    h2 = hash_password(test_password)
    if h == h2:
        print("WARN — hash_password() produced the same output twice for the same input.")
        print("       This suggests you are not using a random salt.")
    else:
        print("  Two hashes of the same password are different (random salt) ✓")

    print("\nAll tests passed. Your implementation looks correct.")
