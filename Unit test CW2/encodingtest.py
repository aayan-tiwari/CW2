from encoding import encode_data
import pytest
class TestEncodeData:
    def test_base64_encoding(self):
        data = "Hello World"
        encoding_type = "base64"
        expected_result = "SGVsbG8gV29ybGQ="
        result = encode_data(data, encoding_type)
        assert result == expected_result
    def test_hex_encoding(self):
        data = "Hello World"
        encoding_type = "hex"
        expected_result = "48656c6c6f20576f726c64"
        result = encode_data(data, encoding_type)
        assert result == expected_result
    def test_rot13_encoding(self):
        data = "Hello World"
        encoding_type = "rot13"
        expected_result = "Uryyb Jbeyq"
        result = encode_data(data, encoding_type)
        assert result == expected_result
    def test_empty_data(self):
        data = ""
        encoding_type = "base64"
        expected_result = ""
        result = encode_data(data, encoding_type)
        assert result == expected_result
    def test_binary_encoding(self):
        data = "Hello World"
        encoding_type = "binary"
        expected_result = "01001000 01100101 01101100 01101100 01101111 00100000 01010111 01101111 01110010 01101100 01100100"
        result = encode_data(data, encoding_type)
        assert result == expected_result
    def test_url_encoding_fixed(self):
        data = "Hello World"
        encoding_type = "url"
        expected_result = "Hello+World"
        result = encode_data(data, encoding_type)
        assert result == expected_result
    def test_morse_encoding(self):
        data = "Hello World"
        encoding_type = "morse"
        expected_result = ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."
        result = encode_data(data, encoding_type)
        assert result == expected_result

        