import ctypes
import os
import sys
sys.path.append('./lib/pythonrijndael')
import aes as py_aes
import time

# Load the shared library
c_aes = ctypes.CDLL('./rijndael.so')

def generate_random_plaintext(length):
    """use epoch time as the source of randomness"""
    epoch = str(time.time())
    number_str = epoch.replace(".","")
    result = []
    i = 0
    while i < len(number_str):
        if number_str[i] == '0' and i < len(number_str) - 1:
            result.append(int(number_str[i:i+1]))  # Take one character
            i += 1
        else:
            if i == len(number_str) - 1:
                result.append(int(number_str[i:i+1]))
            else:
                result.append(int(number_str[i:i+2]))
            i += 2
    return result[:length]


c_aes.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
c_aes.restype = ctypes.c_char_p


def test_aes_encryption():
    for _ in range(3):  # Generate at least 3 random inputs
        plaintext = generate_random_plaintext(16)  # AES block size
        key = generate_random_plaintext(16)   # Assuming AES-128 for simplicity
    
        py_ciphertext = py_aes.encrypt(bytes(key), bytes(plaintext))
        print("debug 1")
        c_ciphertext = c_aes.aes_encrypt_block(bytes(plaintext), bytes(key))
        print("debug 2")

        print("Python ciphertext", py_ciphertext)
        print("C ciphertext", c_ciphertext)
        # Compare outputs
        
        assert py_ciphertext == ctypes.string_at(c_ciphertext, 16)

test_aes_encryption()
"""
class TestBlock(unittest.TestCase):
"""
    #Tests raw AES-128 block operations.
"""
    def setUp(self):
        self.aes = AES(b'\x00' * 16)

    def test_success(self):
""" 
        #Should be able to encrypt and decrypt block messages. 
"""
        message = b'\x01' * 16
        ciphertext = self.aes.encrypt_block(message)
        self.assertEqual(self.aes.decrypt_block(ciphertext), message)

        message = b'a secret message'
        ciphertext = self.aes.encrypt_block(message)
        self.assertEqual(self.aes.decrypt_block(ciphertext), message)
"""