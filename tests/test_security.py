from unittest.mock import MagicMock

import pytest

from pyhelpers_daevski.security import (
    FILE_PERMISSIONS,
    HASH_LEN,
    SALT_LENGTH,
    deserialize_key,
    encrypt_password,
    generate_salt,
    hash_password,
    read_password_hash_from_file,
    serialize_key,
    verify_password,
    write_password_hash_to_file,
)

testdata_passwords: list = [
    "!fzn8!SB",  # 8 char
    "BH9NG3^ycG!D$taD",  # 16 char
    "kk4xIT9nNhW4@v#raFo4",  # 20 char
    "*okacmSDjWNyCumw#qPWN3qGMd2^D2Cshw%gWokky^AB6g7pT*&tc9u@H#"
    "^!6HGse8YLQYutB!N*8E",  # 78 char
]

testdata_bad_passwords: list = [
    # 7 char (too small)
    (
        "8Q9gQ*a",
        {
            "password_ok": False,
            "length_error": True,
            "digit_error": False,
            "uppercase_error": False,
            "lowercase_error": False,
            "symbol_error": False,
        },
    ),
    # 7 char, no digits
    (
        "QQQgQ*a",
        {
            "password_ok": False,
            "length_error": True,
            "digit_error": True,
            "uppercase_error": False,
            "lowercase_error": False,
            "symbol_error": False,
        },
    ),
    # 8 char, no symbols
    (
        "ffzn88SB",
        {
            "password_ok": False,
            "length_error": False,
            "digit_error": False,
            "uppercase_error": False,
            "lowercase_error": False,
            "symbol_error": True,
        },
    ),
    # 9 char, no uppercase
    (
        "!fzn8!sbb",
        {
            "password_ok": False,
            "length_error": False,
            "digit_error": False,
            "uppercase_error": True,
            "lowercase_error": False,
            "symbol_error": False,
        },
    ),
    # 9 char, no lowercase
    (
        "!FZN8!SBB",
        {
            "password_ok": False,
            "length_error": False,
            "digit_error": False,
            "uppercase_error": False,
            "lowercase_error": True,
            "symbol_error": False,
        },
    ),
]


def test_generate_salt_returns_bytes_length():
    result = generate_salt()
    assert len(result) == SALT_LENGTH
    assert isinstance(result, bytes)


@pytest.mark.parametrize("password", testdata_passwords)
def test_hash_password(password: str):
    # Setup
    salt = generate_salt()
    # Act
    result = hash_password(password, salt)
    # Assert
    assert isinstance(result, bytes)
    assert len(result) == HASH_LEN


@pytest.mark.parametrize("password", testdata_passwords)
def test_encrypt(password: str):
    # Setup
    salt = generate_salt()
    app_key = hash_password(password, salt)
    # Act
    result = encrypt_password(password, salt)
    # Assert
    assert app_key == result


# verify_password simple uses hash_password, and this test proves that.
@pytest.mark.parametrize("password", testdata_passwords)
def test_verify_password(password):
    # Setup
    salt = generate_salt()
    key = hash_password(password, salt)
    # Act
    result = verify_password(key, password, salt)
    # Assert

    assert result is True


def test_serialze_key_uses_bytes_hex():
    # Setup
    expected = b"test".hex()
    # Act
    result = serialize_key(b"test")
    # Assert
    assert result == expected


def test_deserialze_key_uses_bytes_fromhex():
    # Setup
    expected = bytes.fromhex(b"test".hex())
    # Act
    result = deserialize_key(b"test".hex())
    # Assert
    assert result == expected


def test_write_password_hash_to_file():
    # Setup
    filepath = MagicMock()
    key = b"test-key"
    salt = b"salt"
    # Act
    write_password_hash_to_file(filepath, key, salt)
    # Assert
    filepath.open.assert_called_once_with("w")
    filepath.open.return_value.__enter__().write.assert_called()
    filepath.chmod.assert_called_once_with(FILE_PERMISSIONS)


def test_read_password_hash_from_file():
    # Setup
    filepath = MagicMock()
    key = b"test-key"
    salt = b"salt"
    filepath.open.return_value.__enter__().readlines.side_effect = [
        [f"Salt: {salt.hex()}\n", f"Password Hash: {key.hex()}\n"]
    ]
    # Act
    result_key, result_salt = read_password_hash_from_file(filepath)
    # Assert
    filepath.open.assert_called_once_with("r")
    assert result_key == key
    assert result_salt == salt


# @pytest.mark.parametrize("password", testdata_passwords)
# def test_key_from_password(password: str):
#     # Setup
#     password_provided = password

#     # Act
#     result = key_from_password(password_provided)

#     # Assert
#     assert type(result) == bytes
#     assert len(result) == 44
#     assert result.decode() != password_provided

# @pytest.mark.parametrize("password", testdata_passwords)
# def test_decrypt(password: str):
#     # Setup
#     app_key = key_from_password("app_pass")
#     sensitive = password
#     enc_pass = encrypt(sensitive, app_key)

#     # Act
#     result = decrypt(enc_pass, app_key)

#     # Assert
#     assert type(result) == bytes
#     assert result.decode() == sensitive


# # @patch('pyhelpers_daevski.security.Path')
# def test_get_local_pw_hash():
#     # Setup
#     m_hash = "123456"
#     pw_hash_file = MagicMock()
#     pw_hash_file.open.return_value.__enter__.return_value.read.return_value = m_hash

#     # Act
#     result = get_local_pw_hash(pw_hash_file)

#     # Assert
#     assert result == m_hash
#     pw_hash_file.open.call_count == 1
#     assert pw_hash_file.open.return_value.__enter__.return_value.method_calls == [
#         call.read()
#     ]


# @pytest.mark.parametrize("password", testdata_passwords)
# def test_verify_password(password: str):
#     # Setup
#     _hash = hash_password(password)

#     # Act
#     result = verify_pwd_hash(_hash, password)

#     # Assert
#     assert result is True


# @pytest.mark.parametrize("bad_pass, error_dict", testdata_bad_passwords)
# @pytest.mark.parametrize("ok_pass", testdata_passwords)
# def test_pwd_requirements_check(ok_pass, bad_pass, error_dict):
#     # Setup
#     ok_dict = {
#         "password_ok": True,
#         "length_error": False,
#         "digit_error": False,
#         "uppercase_error": False,
#         "lowercase_error": False,
#         "symbol_error": False,
#     }

#     # Act
#     ok_result = pwd_requirements_check(ok_pass)
#     bad_result = pwd_requirements_check(bad_pass)

#     assert ok_result == ok_dict
#     assert bad_result == error_dict


# @patch("pyhelpers_daevski.security.print")
# @patch("pyhelpers_daevski.security.verify_pwd_hash")
# @patch("pyhelpers_daevski.security.pwinput")
# class TestAppPassPrompt:
#     def test_application_password_prompt_pass_correct_first_attempt(
#         self, m_pwinput, m_verify_pwd_hash, m_print
#     ):
#         # Setup
#         pwhash = "pwhash"
#         provided_passes = ["pass1"]
#         m_pwinput.side_effect = (p for p in provided_passes)
#         m_verify_pwd_hash.side_effect = (v for v in (True,))
#         expected_pwinput_calls = 1
#         expected_verify_pwd_calls = 1
#         expected_print_calls = 0

#         # Act
#         result = application_password_prompt(pwhash)

#         # Assert
#         assert m_pwinput.call_count == expected_pwinput_calls
#         assert m_verify_pwd_hash.call_count == expected_verify_pwd_calls
#         assert m_print.call_count == expected_print_calls
#         assert result == provided_passes[0]

#     def test_application_password_prompt_existing_pass_correct_second_attempt(
#         self, m_pwinput, m_verify_pwd_hash, m_print
#     ):
#         # Setup
#         pwhash = "pwhash"
#         provided_passes = ["pass2", "pass1"]
#         m_pwinput.side_effect = (p for p in provided_passes)
#         m_verify_pwd_hash.side_effect = (v for v in (False, True))
#         expected_pwinput_calls = 2
#         expected_verify_pwd_calls = 2
#         expected_print_calls = 1

#         # Act
#         result = application_password_prompt(pwhash)

#         # Assert
#         assert m_pwinput.call_count == expected_pwinput_calls
#         assert m_verify_pwd_hash.call_count == expected_verify_pwd_calls
#         assert m_print.call_count == expected_print_calls
#         assert result == provided_passes[-1]

#     def test_application_password_prompt_existing_pass_correct_third_attempt(
#         self, m_pwinput, m_verify_pwd_hash, m_print
#     ):
#         # Setup
#         pwhash = "pwhash"
#         provided_passes = ["pass2", "pass2", "pass1"]
#         m_pwinput.side_effect = (p for p in provided_passes)
#         m_verify_pwd_hash.side_effect = (v for v in (False, False, True))
#         expected_pwinput_calls = 3
#         expected_verify_pwd_calls = 3
#         expected_print_calls = 2

#         # Act
#         result = application_password_prompt(pwhash)

#         # Assert
#         assert m_pwinput.call_count == expected_pwinput_calls
#         assert m_verify_pwd_hash.call_count == expected_verify_pwd_calls
#         assert m_print.call_count == expected_print_calls
#         assert result == provided_passes[-1]

#     def test_application_password_prompt_existing_pass_fail_max_attempts(
#         self, m_pwinput, m_verify_pwd_hash, m_print
#     ):
#         # Setup
#         pwhash = "pwhash"
#         provided_passes = ["pass2", "pass2", "pass2"]
#         m_pwinput.side_effect = (p for p in provided_passes)
#         m_verify_pwd_hash.side_effect = (v for v in [False, False, False])
#         exceeded_attempts_exit_msg = "Could not login; " "Password is not correct."
#         expected_pwinput_calls = 3
#         expected_verify_pwd_calls = 3
#         expected_print_calls = 3

#         # Act
#         with pytest.raises(SystemExit) as exit_with_msg:
#             application_password_prompt(pwhash)

#         # Assert
#         assert m_pwinput.call_count == expected_pwinput_calls
#         assert m_verify_pwd_hash.call_count == expected_verify_pwd_calls
#         assert m_print.call_count == expected_print_calls
#         assert str(exit_with_msg.value) == exceeded_attempts_exit_msg


# # --- End TestAppPassPrompt class


# @patch("pyhelpers_daevski.security.create_hash")
# @patch("pyhelpers_daevski.security.pwinput")
# class TestAppPassNewPrompt:
#     def test_application_password_prompt_new_password_confirm_success(
#         self, m_pwinput, m_create_hash
#     ):
#         # Setup
#         pwhash_filename = "hashfile"
#         provided_passes = ["pass1", "pass1"]
#         m_pwinput.side_effect = (p for p in provided_passes)
#         expected_pwinput_calls = 2
#         expected_createhash_calls = 1

#         # Act
#         result = application_password_prompt_new(pwhash_filename)

#         # Assert
#         assert m_pwinput.call_count == expected_pwinput_calls
#         assert m_create_hash.call_count == expected_createhash_calls
#         assert result == provided_passes[0]

#     def test_application_password_prompt_new_password_confirm_fail(
#         self, m_pwinput, m_create_hash
#     ):
#         # Setup
#         pwhash_filename = "hashfile"
#         provided_passes = ["pass1", "pass2"]
#         m_pwinput.side_effect = (p for p in provided_passes)
#         exit_msg = "*Buzzer* Nope, no dice."
#         expected_pwinput_calls = 2
#         expected_createhash_calls = 0

#         # Act
#         with pytest.raises(SystemExit) as exit_with_msg:
#             application_password_prompt_new(pwhash_filename)

#         # Assert
#         assert m_pwinput.call_count == expected_pwinput_calls
#         assert m_create_hash.call_count == expected_createhash_calls
#         assert str(exit_with_msg.value) == exit_msg


# --- End TestAppPassNewPrompt class
