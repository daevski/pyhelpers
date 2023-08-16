import re
from pathlib import Path

import pwinput

from pyhelpers_daevski.security import (
    encrypt_password,
    generate_salt,
    hash_password,
    read_password_hash_from_file,
    verify_password,
    write_password_hash_to_file,
)


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
    symbol_error = re.search(r"\W", password) is None

    # overall result
    password_ok = not (
        length_error
        or digit_error
        or uppercase_error
        or lowercase_error
        or symbol_error
    )

    return {
        "password_ok": password_ok,
        "length_error": length_error,
        "digit_error": digit_error,
        "uppercase_error": uppercase_error,
        "lowercase_error": lowercase_error,
        "symbol_error": symbol_error,
    }


def application_password_prompt_new(password_file: Path) -> bytes:
    _prompt_text = (
        "A password is considered acceptable if it has: \n"
        "8 characters length or more\n"
        "1 digit or more\n"
        "1 uppercase letter or more\n"
        "1 lowercase letter or more.\n\n"
        "New application password: "
    )
    provided_password = pwinput(prompt=_prompt_text, mask="*")
    confirmation_password = pwinput(prompt="Enter it again to confirm: ", mask="*")
    if not provided_password == confirmation_password:
        exit("*Buzzer* Nope, no dice.")

    salt = generate_salt()
    stored_key = encrypt_password(provided_password, salt)
    write_password_hash_to_file(password_file, stored_key, salt)
    return hash_password(provided_password, salt)


def application_password_prompt(password_file: Path) -> bytes:
    _incorrect_password_message = "Password not correct; please try again."
    _prompt_text = "Application password: "
    _password_attempts = 3
    _password_match = False

    stored_key, salt = read_password_hash_from_file(password_file)

    attempt = 1
    while attempt <= _password_attempts:
        provided_password = pwinput(prompt=_prompt_text, mask="*")
        if not verify_password(stored_key, provided_password, salt):
            print(_incorrect_password_message)
            attempt += 1
            continue
        _password_match = True
        break

    if not _password_match:
        exit("Could not login; Password is not correct.")

    return hash_password(provided_password, salt)
