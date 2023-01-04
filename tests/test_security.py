import re
from typing import Match
from unittest.mock import MagicMock, call, patch

import pytest

from pyhelpers_daevski.security import (
    application_password_prompt,
    application_password_prompt_new,
    create_hash,
    decrypt,
    encrypt,
    get_local_pw_hash,
    hash_password,
    key_from_password,
    pwd_requirements_check,
    verify_pwd_hash,
)

testdata_passwords: list = [
    '!fzn8!SB',  # 8 char
    'BH9NG3^ycG!D$taD',  # 16 char
    'kk4xIT9nNhW4@v#raFo4',  # 20 char
    '*okacmSDjWNyCumw#qPWN3qGMd2^D2Cshw%gWokky^AB6g7pT*&tc9u@H#' '^!6HGse8YLQYutB!N*8E',  # 78 char
]

testdata_bad_passwords: list = [
    # 7 char (too small)
    (
        '8Q9gQ*a',
        {
            'password_ok': False,
            'length_error': True,
            'digit_error': False,
            'uppercase_error': False,
            'lowercase_error': False,
            'symbol_error': False,
        },
    ),
    # 7 char, no digits
    (
        'QQQgQ*a',
        {
            'password_ok': False,
            'length_error': True,
            'digit_error': True,
            'uppercase_error': False,
            'lowercase_error': False,
            'symbol_error': False,
        },
    ),
    # 8 char, no symbols
    (
        'ffzn88SB',
        {
            'password_ok': False,
            'length_error': False,
            'digit_error': False,
            'uppercase_error': False,
            'lowercase_error': False,
            'symbol_error': True,
        },
    ),
    # 9 char, no uppercase
    (
        '!fzn8!sbb',
        {
            'password_ok': False,
            'length_error': False,
            'digit_error': False,
            'uppercase_error': True,
            'lowercase_error': False,
            'symbol_error': False,
        },
    ),
    # 9 char, no lowercase
    (
        '!FZN8!SBB',
        {
            'password_ok': False,
            'length_error': False,
            'digit_error': False,
            'uppercase_error': False,
            'lowercase_error': True,
            'symbol_error': False,
        },
    ),
]


@pytest.mark.parametrize('password', testdata_passwords)
def test_key_from_password(password: str):
    # Setup
    password_provided = password

    # Act
    result = key_from_password(password_provided)

    # Assert
    assert type(result) == bytes
    assert len(result) == 44
    assert result.decode() != password_provided


@pytest.mark.parametrize('password', testdata_passwords)
def test_encrypt(password: str):
    # Setup
    app_key = key_from_password('app_pass')
    sensitive = password

    # Act
    result = encrypt(sensitive, app_key)

    # Assert
    assert type(result) == bytes
    assert len(result) >= 100
    assert decrypt(result, app_key) == sensitive.encode()


@pytest.mark.parametrize('password', testdata_passwords)
def test_decrypt(password: str):
    # Setup
    app_key = key_from_password('app_pass')
    sensitive = password
    enc_pass = encrypt(sensitive, app_key)

    # Act
    result = decrypt(enc_pass, app_key)

    # Assert
    assert type(result) == bytes
    assert result.decode() == sensitive


# @patch('pyhelpers_daevski.security.Path')
def test_get_local_pw_hash():
    # Setup
    m_hash = '123456'
    pw_hash_file = MagicMock()
    pw_hash_file.open.return_value.__enter__.return_value.read.return_value = m_hash

    # Act
    result = get_local_pw_hash(pw_hash_file)

    # Assert
    assert result == m_hash
    pw_hash_file.open.call_count == 1
    assert pw_hash_file.open.return_value.__enter__.return_value.method_calls == [call.read()]


@pytest.mark.parametrize('password', testdata_passwords)
@patch('pyhelpers_daevski.security.open')
@patch('pyhelpers_daevski.security.hash_password', return_value='mock_hash')
def test_create_hash(m_hash_password, m_open, password: str):

    # Setup
    hash_file = MagicMock()
    mock_hash = 'mock_hash'
    provided_password = password

    # Act
    result = create_hash(provided_password, hash_file)

    # Assert
    assert hash_file.open.return_value.__enter__.return_value.method_calls == [
        call.write(mock_hash)
    ]
    assert result == mock_hash


@pytest.mark.parametrize('password', testdata_passwords)
def test_hash_password(password: str):
    # Setup
    regex = r"[a-zA-Z0-9]+"
    password = password

    # Act
    result = hash_password(password)

    # Assert
    assert isinstance(re.fullmatch(regex, result), Match)
    assert len(result) == 192


@pytest.mark.parametrize('password', testdata_passwords)
def test_verify_password(password: str):
    # Setup
    _hash = hash_password(password)

    # Act
    result = verify_pwd_hash(_hash, password)

    # Assert
    assert result is True


@pytest.mark.parametrize('bad_pass, error_dict', testdata_bad_passwords)
@pytest.mark.parametrize('ok_pass', testdata_passwords)
def test_pwd_requirements_check(ok_pass, bad_pass, error_dict):
    # Setup
    ok_dict = {
        'password_ok': True,
        'length_error': False,
        'digit_error': False,
        'uppercase_error': False,
        'lowercase_error': False,
        'symbol_error': False,
    }

    # Act
    ok_result = pwd_requirements_check(ok_pass)
    bad_result = pwd_requirements_check(bad_pass)

    assert ok_result == ok_dict
    assert bad_result == error_dict


@patch('pyhelpers_daevski.security.print')
@patch('pyhelpers_daevski.security.verify_pwd_hash')
@patch('pyhelpers_daevski.security.getpass')
class TestAppPassPrompt:
    def test_application_password_prompt_pass_correct_first_attempt(
        self, m_getpass, m_verify_pwd_hash, m_print
    ):
        # Setup
        pwhash = 'pwhash'
        provided_passes = ['pass1']
        m_getpass.side_effect = (p for p in provided_passes)
        m_verify_pwd_hash.side_effect = (v for v in (True,))
        expected_getpass_calls = 1
        expected_verify_pwd_calls = 1
        expected_print_calls = 0

        # Act
        result = application_password_prompt(pwhash)

        # Assert
        assert m_getpass.call_count == expected_getpass_calls
        assert m_verify_pwd_hash.call_count == expected_verify_pwd_calls
        assert m_print.call_count == expected_print_calls
        assert result == provided_passes[0]

    def test_application_password_prompt_existing_pass_correct_second_attempt(
        self, m_getpass, m_verify_pwd_hash, m_print
    ):

        # Setup
        pwhash = 'pwhash'
        provided_passes = ['pass2', 'pass1']
        m_getpass.side_effect = (p for p in provided_passes)
        m_verify_pwd_hash.side_effect = (v for v in (False, True))
        expected_getpass_calls = 2
        expected_verify_pwd_calls = 2
        expected_print_calls = 1

        # Act
        result = application_password_prompt(pwhash)

        # Assert
        assert m_getpass.call_count == expected_getpass_calls
        assert m_verify_pwd_hash.call_count == expected_verify_pwd_calls
        assert m_print.call_count == expected_print_calls
        assert result == provided_passes[-1]

    def test_application_password_prompt_existing_pass_correct_third_attempt(
        self, m_getpass, m_verify_pwd_hash, m_print
    ):
        # Setup
        pwhash = 'pwhash'
        provided_passes = ['pass2', 'pass2', 'pass1']
        m_getpass.side_effect = (p for p in provided_passes)
        m_verify_pwd_hash.side_effect = (v for v in (False, False, True))
        expected_getpass_calls = 3
        expected_verify_pwd_calls = 3
        expected_print_calls = 2

        # Act
        result = application_password_prompt(pwhash)

        # Assert
        assert m_getpass.call_count == expected_getpass_calls
        assert m_verify_pwd_hash.call_count == expected_verify_pwd_calls
        assert m_print.call_count == expected_print_calls
        assert result == provided_passes[-1]

    def test_application_password_prompt_existing_pass_fail_max_attempts(
        self, m_getpass, m_verify_pwd_hash, m_print
    ):

        # Setup
        pwhash = 'pwhash'
        provided_passes = ['pass2', 'pass2', 'pass2']
        m_getpass.side_effect = (p for p in provided_passes)
        m_verify_pwd_hash.side_effect = (v for v in [False, False, False])
        exceeded_attempts_exit_msg = "Could not login; " "Password is not correct."
        expected_getpass_calls = 3
        expected_verify_pwd_calls = 3
        expected_print_calls = 3

        # Act
        with pytest.raises(SystemExit) as exit_with_msg:
            application_password_prompt(pwhash)

        # Assert
        assert m_getpass.call_count == expected_getpass_calls
        assert m_verify_pwd_hash.call_count == expected_verify_pwd_calls
        assert m_print.call_count == expected_print_calls
        assert str(exit_with_msg.value) == exceeded_attempts_exit_msg


# --- End TestAppPassPrompt class


@patch('pyhelpers_daevski.security.create_hash')
@patch('pyhelpers_daevski.security.getpass')
class TestAppPassNewPrompt:
    def test_application_password_prompt_new_password_confirm_success(
        self, m_getpass, m_create_hash
    ):
        # Setup
        pwhash_filename = 'hashfile'
        provided_passes = ['pass1', 'pass1']
        m_getpass.side_effect = (p for p in provided_passes)
        expected_getpass_calls = 2
        expected_createhash_calls = 1

        # Act
        result = application_password_prompt_new(pwhash_filename)

        # Assert
        assert m_getpass.call_count == expected_getpass_calls
        assert m_create_hash.call_count == expected_createhash_calls
        assert result == provided_passes[0]

    def test_application_password_prompt_new_password_confirm_fail(self, m_getpass, m_create_hash):
        # Setup
        pwhash_filename = 'hashfile'
        provided_passes = ['pass1', 'pass2']
        m_getpass.side_effect = (p for p in provided_passes)
        exit_msg = "*Buzzer* Nope, no dice."
        expected_getpass_calls = 2
        expected_createhash_calls = 0

        # Act
        with pytest.raises(SystemExit) as exit_with_msg:
            application_password_prompt_new(pwhash_filename)

        # Assert
        assert m_getpass.call_count == expected_getpass_calls
        assert m_create_hash.call_count == expected_createhash_calls
        assert str(exit_with_msg.value) == exit_msg


# --- End TestAppPassNewPrompt class
