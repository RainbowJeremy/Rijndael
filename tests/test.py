import ctypes
import os
import sys
sys.path.append('./lib/pythonrijndael')
import aes as py_aes
import time
import unittest

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
    print(result[:length])
    return result[:length]

def try_gen():
    secure_random_bytes = os.urandom(16)
    secure_random_byte_list = list(secure_random_bytes)
    return secure_random_byte_list

def hello():
    plaintext = (ctypes.c_ubyte * 16)(*range(1, 17))
    key = (ctypes.c_ubyte * 16)(50, 20, 46, 86, 67, 9, 70, 27, 75, 17, 51, 17, 4, 8, 6, 99)
    ciphertext = (ctypes.c_ubyte * 16)()  
    recovered_plaintext = (ctypes.c_ubyte * 16)() 

    plaintext = (ctypes.c_ubyte * 16)(*range(1, 17))
    #key = (ctypes.c_ubyte * 16)(50, 20, 46, 86, 67, 9, 70, 27, 75, 17, 51, 17, 4, 8, 6, 99)
    random_key_bytes = generate_random_plaintext(16)
    key = (ctypes.c_ubyte * 16)(*random_key_bytes)
    ciphertext = (ctypes.c_ubyte * 16)()  
    recovered_plaintext = (ctypes.c_ubyte * 16)()  
    print("key", list(key))

    aa = c_aes.aes_encrypt_block(plaintext, key)
    print("no bug!", aa)
    return



"""
c_aes.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
c_aes.restype = ctypes.c_char_p
"""

c_aes.aes_encrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
c_aes.aes_decrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
class TestStringMethods(unittest.TestCase):
    def test_upper(self):
            self.assertEqual('foo'.upper(), 'FOO')

    def test_subbytes(self):
        for _ in range(3):
            plaintext = generate_random_plaintext(16)
            c = plaintext.copy()
            square_s_box = [c[:4],c[4:8],c[8:12],c[12:16]]
            plaintext = try_gen()
            copied_plaintext = plaintext.copy()
            sq_plaintext = [copied_plaintext[:4],copied_plaintext[4:8],copied_plaintext[8:12],copied_plaintext[12:16]]
            a = c_aes.sub_bytes(bytes(plaintext))
            py_aes.sub_bytes(sq_plaintext)
            print("a", a, sq_plaintext)

#test_subbytes()
unittest.main()

def new_test():
    plaintext = (ctypes.c_ubyte * 16)(*range(1, 17))
    #key = (ctypes.c_ubyte * 16)(50, 20, 46, 86, 67, 9, 70, 27, 75, 17, 51, 17, 4, 8, 6, 99)
    random_key_bytes = generate_random_plaintext(16)
    key = (ctypes.c_ubyte * 16)(*random_key_bytes)
    ciphertext = (ctypes.c_ubyte * 16)()  
    recovered_plaintext = (ctypes.c_ubyte * 16)()  
    print("key", key)

    aa = c_aes.aes_encrypt_block(plaintext, key)
    print("no bug!", aa)
    return



def test_aes_encryption():
    for _ in range(3):  # Generate at least 3 random inputs
        plaintext = generate_random_plaintext(16)  # AES block size
        key = generate_random_plaintext(16)   # Assuming AES-128 for simplicity
        plaintext = [1 for _ in range(16)]  
        key = [1 for _ in range(16)]  
        

        py_ciphertext = py_aes.encrypt(bytes(key), bytes(plaintext))
        print("debug 1")
        c_ciphertext = c_aes.aes_encrypt_block(bytes(plaintext), bytes(key))
        print("debug 2")

        print("Python ciphertext", py_ciphertext)
        print("C ciphertext", c_ciphertext)
        # Compare outputs
        assert py_ciphertext == ctypes.string_at(c_ciphertext, 16)

new_test()
#test_aes_encryption()
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