import os
import random
import string


def generate_text_file(file_path, file_size_bytes):
    """Generate a text file with given file size."""
    with open(file_path, 'wb') as file:
        text_to_right = os.urandom(file_size_bytes)
        file.write(text_to_right)

# Example usage
file_path = f'random_text.txt'
file_size_bytes = 8  # Size in bytes
generate_text_file(file_path, file_size_bytes)
print(f"Generated text file '{file_path}' with size {os.path.getsize(file_path)} bytes.")
