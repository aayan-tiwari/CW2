import argparse
import base64
import binascii
import codecs
import urllib.parse

def encode_data(data, encoding_type):
    try:
        if encoding_type == 'base64':
            return base64.b64encode(data.encode()).decode()
        elif encoding_type == 'hex':
            return binascii.hexlify(data.encode()).decode()
        elif encoding_type == 'rot13':
            return codecs.encode(data, 'rot_13')
        elif encoding_type == 'binary':
            return ' '.join(format(ord(char), '08b') for char in data)
        elif encoding_type == 'url':
            return urllib.parse.quote_plus(data)
        elif encoding_type == 'morse':
            morse_code_dict = {'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....',
                               'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.',
                               'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
                               'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
                               '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', ' ': '/'}
            return ' '.join(morse_code_dict.get(char.upper(), char) for char in data)
        elif encoding_type == 'a1z26':
            return ' '.join(str(ord(char) - ord('A') + 1) if char.isalpha() else char for char in data)
        else:
            raise ValueError("Invalid encoding type")
    except UnicodeEncodeError:
        return "Error: Unable to encode some characters in the input data"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description='Encode data using various encoding techniques.')
    parser.add_argument('--data', help='Data to encode')
    parser.add_argument('--encoding_type', choices=['base64', 'hex', 'rot13', 'binary', 'url', 'morse', 'a1z26'], help='Type of encoding')

    args = parser.parse_args()

    data = args.data or input("Enter the data to encode: ")
    encoding_type = args.encoding_type or input("Enter the encoding type: ")

    result = encode_data(data, encoding_type)
    print(result)

if __name__ == '__main__':
    main()
