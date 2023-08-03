#!/usr/bin/env python3
"""A module for secure password encryption using bcrypt.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Encrypts a password using a randomly generated salt.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Checks if a hashed password matches the given password.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
