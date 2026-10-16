from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

hasher = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)

def hash_password(password: str) -> str:
    """Return a secure hash of password suitable for storing in a database."""
    return hasher.hash(password)

def verify_password(password: str, stored_hash: str) -> bool:
    """Return True if password matches stored_hash, False otherwise."""
    try:
        hasher.verify(stored_hash, password)
        return True
    except VerifyMismatchError:
        return False

if __name__ == "__main__":
    test_password = "Hunter2!"
    wrong_password = "not_the_right_password"
    print("Testing hash_password() and verify_password()...")
    h = hash_password(test_password)
    print(f"  hash_password() returned: {h[:30]}...")
    result_correct = verify_password(test_password, h)
    print(f"  verify_password(correct_password, hash) -> {result_correct}")
    result_wrong = verify_password(wrong_password, h)
    print(f"  verify_password(wrong_password, hash) -> {result_wrong}")
    h2 = hash_password(test_password)
    print(f"  Two hashes identical: {h == h2}")
