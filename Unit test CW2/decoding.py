import base64
import binascii
import codecs
import urllib.parse

def decode_data(encoded_data, encoding_type):
    try:
        if encoding_type == 'base64':
            return base64.b64decode(encoded_data).decode()
        elif encoding_type == 'hex':
            return binascii.unhexlify(encoded_data).decode()
        elif encoding_type == 'rot13':
            return codecs.decode(encoded_data, 'rot_13')
        elif encoding_type == 'binary':
            binary_list = encoded_data.split()
            return ''.join(chr(int(binary, 2)) for binary in binary_list)
        elif encoding_type == 'url':
            return urllib.parse.unquote_plus(encoded_data)
        elif encoding_type == 'morse':
            morse_code_dict = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
                               '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
                               '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
                               '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
                               '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9'}
            morse_list = encoded_data.split(' ')
            return ''.join(morse_code_dict.get(morse, morse) for morse in morse_list)
        elif encoding_type == 'a1z26':
            a1z26_list = encoded_data.split()
            return ''.join(chr(int(char) + ord('A') - 1) if char.isdigit() else char for char in a1z26_list)
        else:
            raise ValueError("Invalid encoding type")
    except binascii.Error:
        return "Error: Invalid hexadecimal string"
    except UnicodeDecodeError:
        return "Error: Unable to decode some characters in the input data"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    encoded_data = input("Enter the encoded data: ")
    encoding_type = input("Enter the encoding type: ")

    result = decode_data(encoded_data, encoding_type)
    print(result)

if __name__ == '__main__':
    main()
