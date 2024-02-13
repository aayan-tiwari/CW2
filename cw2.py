import tkinter as tk
from tkinter import ttk, messagebox, filedialog
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
                               '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.'}
            return ' '.join(morse_code_dict.get(char.upper(), char) for char in data)
        elif encoding_type == 'a1z26':
            return ' '.join(str(ord(char) - ord('A') + 1) if char.isalpha() else char for char in data)
        else:
            raise ValueError("Invalid encoding type")
    except UnicodeEncodeError:
        return "Error: Unable to encode some characters in the input data"
    except Exception as e:
        return f"Error: {str(e)}"
    
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
    
def all_operations(operation, data):
    result = ""
    for encoding_type in ['base64', 'hex', 'rot13', 'binary', 'url', 'morse', 'a1z26']:
        try:
            if operation == 'decode':
                decoded_data = decode_data(data, encoding_type)
                if not decoded_data.startswith("Error"):
                    result += f"{encoding_type.capitalize()} Decoded Data: {decoded_data}\n"
            elif operation == 'encode':
                encoded_data = encode_data(data, encoding_type)
                result += f"{encoding_type.capitalize()} Encoded Data: {encoded_data}\n"
        except Exception:
            pass  # If decoding/encoding results in an error, skip to the next method
    return result

def execute_operation():
    operation = operation_var.get()
    data = input_data_entry.get()
    encoding_type = encoding_var.get()

    if operation == 'decode' and encoding_type == 'all':
        result_data = all_operations(operation, data)
        output_text.delete('1.0', tk.END)
        output_text.insert(tk.END, result_data)
    elif operation == 'encode' and encoding_type == 'all':
        result_data = all_operations(operation, data)
        output_text.delete('1.0', tk.END)
        output_text.insert(tk.END, result_data)
    elif operation == 'decode':
        result_data = decode_data(data, encoding_type)
        output_text.delete('1.0', tk.END)
        output_text.insert(tk.END, f"Decoded Data: {result_data}")
    elif operation == 'encode':
        result_data = encode_data(data, encoding_type)
        output_text.delete('1.0', tk.END)
        output_text.insert(tk.END, f"Encoded Data: {result_data}")
    else:
        output_text.delete('1.0', tk.END)
        output_text.insert(tk.END, "Invalid operation or encoding type.")

def clear_output():
    output_text.delete('1.0', tk.END)

def save_result():
    result = output_text.get('1.0', tk.END)
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(result)

def show_help():
    messagebox.showinfo("Help", "Project Documentation:\n\nThis tool allows you to encode and decode data using various encoding types such as base64, hex, rot13, binary, url, morse, and a1z26.\n\nUsage:\n1. Select the operation (encode or decode).\n2. Enter the input data.\n3. Select the encoding type.\n4. Click the 'Execute' button to perform the operation.\n5. View the result in the text area.\n\nYou can also save the result to a text file using the 'Save' option in the File menu.")

root = tk.Tk()
root.title("Cryptography Tool")

file_menu = tk.Menu(menu_bar, tearoff=False)
menu_bar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Save", command=save_result)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)