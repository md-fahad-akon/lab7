from unittest import mock

import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.entities import InvalidParamError
from presidio_anonymizer.operators import OperatorType


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text",
                                        params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b'1111111111111111'})


def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})

def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised():
    # Use a bytes key that is actually invalid length (not 16, 24, or 32 bytes)
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'invalid'})  # Only 7 bytes

def test_operator_name():
    operator = Encrypt()
    assert operator.operator_name() == "encrypt"

def test_operator_type():
    operator = Encrypt()
    assert operator.operator_type() == OperatorType.Encrypt

@pytest.mark.parametrize("key", [
    "1111111111111111",  # 128 bits (16 bytes) string
    "111111111111111111111111",  # 192 bits (24 bytes) string
    "11111111111111111111111111111111",  # 256 bits (32 bytes) string
    b'1111111111111111',  # 128 bits (16 bytes) bytes
    b'111111111111111111111111',  # 192 bits (24 bytes) bytes
    b'11111111111111111111111111111111',  # 256 bits (32 bytes) bytes
])
def test_valid_keys(key):
    # Should not raise an exception
    Encrypt().validate(params={"key": key})