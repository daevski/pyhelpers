import os
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# from typing import Tuple

SALT_LENGTH = 16
NUM_ITERATIONS = 100000
HASH_LEN = 32
FILE_PERMISSIONS = 0o600


def generate_salt() -> bytes:
    return os.urandom(SALT_LENGTH)


def hash_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=NUM_ITERATIONS,
        salt=salt,
        length=HASH_LEN,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode())
    return key


def encrypt_password(password: str, salt: bytes) -> bytes:
    key = hash_password(password, salt)
    return key


def verify_password(stored_key: bytes, password: str, salt: bytes) -> bool:
    key = hash_password(password, salt)
    return key == stored_key


def serialize_key(key: bytes) -> str:
    return key.hex()


def deserialize_key(serialized_key: str) -> bytes:
    return bytes.fromhex(serialized_key)


def write_password_hash_to_file(filepath: Path, stored_key: bytes, salt: bytes) -> None:
    with filepath.open("w") as file:
        file.write(f"Salt: {serialize_key(salt)}\n")
        file.write(f"Password Hash: {serialize_key(stored_key)}\n")
    filepath.chmod(
        FILE_PERMISSIONS
    )  # Set file permissions to be readable/writable only by the owner


def read_password_hash_from_file(filepath: Path) -> tuple[bytes, bytes]:
    with filepath.open("r") as file:
        lines = file.readlines()
        salt = deserialize_key(lines[0].split(": ")[1].strip())
        stored_key = deserialize_key(lines[1].split(": ")[1].strip())
    return stored_key, salt
