#!/usr/bin/env python3
""" Utility functions for password
hashing and validation using bcrypt """
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt with a generated salt.

    Args:
        password (str): The plaintext password to hash.

    Returns:
        bytes: A salted, hashed password as a byte string.

    Example:
        >>> hashed = hash_password("my_password")
    """
    # Encode the password to bytes and hash it with a generated salt
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates if a provided password matches the stored hashed password.

    Args:
        hashed_password (bytes): The previously hashed password.
        password (str): The plaintext password to validate.

    Returns:
        bool: True if the password matches the hash, False otherwise.

    Example:
        >>> hashed = hash_password("my_password")
        >>> is_valid(hashed, "my_password")
        True
    """
    # Compare the plaintext password (encoded) with the stored hash
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
