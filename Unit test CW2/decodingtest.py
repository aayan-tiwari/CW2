import base64
from decoding import decode_data
import binascii
import codecs
import pytest
class TestDecodeData:
    def test_decoding_base64(self):
        encoded_data = base64.b64encode(b'Test').decode()
        encoding_type = 'base64'
        expected_result = 'Test'
        result = decode_data(encoded_data, encoding_type)
        assert result == expected_result
    def test_decoding_hexadecimal(self):
        encoded_data = binascii.hexlify(b'Test').decode()
        encoding_type = 'hex'
        expected_result = 'Test'
        result = decode_data(encoded_data, encoding_type)
        assert result == expected_result
    def test_decoding_rot13(self):
        encoded_data = codecs.encode('Test', 'rot_13')
        encoding_type = 'rot13'
        expected_result = 'Test'
        result = decode_data(encoded_data, encoding_type)
        assert result == expected_result
    def test_decoding_invalid_hexadecimal(self):
        encoded_data = 'ZZ'
        encoding_type = 'hex'
        expected_result = 'Error: Invalid hexadecimal string'
        result = decode_data(encoded_data, encoding_type)
        assert result == expected_result
    def test_decoding_invalid_characters(self):
        encoded_data = 'Test'
        encoding_type = 'binary'
        expected_result = "Error: invalid literal for int() with base 2: 'Test'"
        result = decode_data(encoded_data, encoding_type)
        assert result == expected_result
    def test_decoding_invalid_encoding_type(self):
        encoded_data = 'Test'
        encoding_type = 'invalid'
        expected_result = 'Error: Invalid encoding type'
        result = decode_data(encoded_data, encoding_type)
        assert result == expected_result

        