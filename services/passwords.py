"""Password hashing helpers (bcrypt).

Passwords are never stored or returned in plain text. bcrypt only uses the first
72 bytes of a password, so longer passwords are rejected at the schema level.
"""
import bcrypt

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_BYTES = 72


def hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Return True if the password matches the stored bcrypt hash.

    Anything that is not a valid bcrypt hash (e.g. a legacy plain-text value)
    never matches, so plain-text passwords can't be used to log in.
    """
    if not plain_password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # Not a bcrypt hash, or password longer than 72 bytes
        return False


def validate_password_strength(value: str) -> str:
    """Used by request schemas for any password being set."""
    if len(value) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(value.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes")
    return value
