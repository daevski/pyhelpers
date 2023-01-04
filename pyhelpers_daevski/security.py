import base64
import binascii
import hashlib
import os
import re
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pwinput import pwinput


def key_from_password(password_provided: str) -> bytes:
    password = password_provided.encode()  # Convert to type bytes
    # TODO: Diff salt for each site password; generate_salt method needed.
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    # Can only use kdf once
    return base64.urlsafe_b64encode(kdf.derive(password))


def encrypt(sensitive: str, key: bytes) -> bytes:
    f = Fernet(key)
    sensitive_bytes = sensitive.encode()
    return f.encrypt(sensitive_bytes)


def decrypt(encrypted: bytes, key: bytes) -> bytes:
    f = Fernet(key)
    return f.decrypt(encrypted)


def get_local_pw_hash(file_path: Path) -> str:
    with file_path.open('r') as f:
        password_hash: str = f.read()
    return password_hash


def create_hash(provided_password: str, pw_hash_file: Path) -> str:
    if not pw_hash_file.parent.exists():
        pw_hash_file.parent.mkdir(parents=True)

    if not pw_hash_file.exists():
        pw_hash_file.touch()

    password_hash: str = hash_password(provided_password)

    with pw_hash_file.open('w') as f:
        f.write(password_hash)

    return password_hash


def hash_password(password: str) -> str:
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def verify_pwd_hash(stored_pwd_hash: str, provided_password: str) -> bool:
    """Verify a stored password hash against
    a hashed password provided by user.
    """
    salt = stored_pwd_hash[:64]
    stored_pwd_hash = stored_pwd_hash[64:]
    pwdhash = hashlib.pbkdf2_hmac(
        'sha512', provided_password.encode('utf-8'), salt.encode('ascii'), 100000
    )
    provided_password = binascii.hexlify(pwdhash).decode('ascii')
    return provided_password == stored_pwd_hash


def pwd_requirements_check(password):
    """
    Verify a password meets or exceeds the minimum requirements.
    Returns a dict indicating the wrong criteria
    A password is considered acceptable if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """

    # calculating the length
    length_error = len(password) < 8

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r'\W', password) is None

    # overall result
    password_ok = not (
        length_error or digit_error or uppercase_error or lowercase_error or symbol_error
    )

    return {
        'password_ok': password_ok,
        'length_error': length_error,
        'digit_error': digit_error,
        'uppercase_error': uppercase_error,
        'lowercase_error': lowercase_error,
        'symbol_error': symbol_error,
    }


def application_password_prompt_new(pw_hash_file: Path) -> str:
    _prompt_text = (
        "A password is considered acceptable if it has: \n"
        "8 characters length or more\n"
        "1 digit or more\n"
        "1 uppercase letter or more\n"
        "1 lowercase letter or more.\n\n"
        "New application password: "
    )
    provided_password = pwinput(prompt=_prompt_text, mask='*')
    confirmation_password = pwinput(prompt="Enter it again to confirm: ", mask='*')
    if not provided_password == confirmation_password:
        exit("*Buzzer* Nope, no dice.")
    create_hash(provided_password, pw_hash_file)
    return provided_password


def application_password_prompt(stored_password_hash: str) -> str:
    _incorrect_password_message = "Password not correct; please try again."
    _prompt_text = "Application password: "
    _password_attempts = 3
    _password_match = False

    attempt = 1
    while attempt <= _password_attempts:
        provided_password = pwinput(prompt=_prompt_text, mask='*')
        if not verify_pwd_hash(stored_password_hash, provided_password):
            print(_incorrect_password_message)
            attempt += 1
            continue
        _password_match = True
        break

    if not _password_match:
        exit("Could not login; Password is not correct.")

    return provided_password
