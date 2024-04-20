import ctypes
import os
import sys
sys.path.append('./lib/pythonrijndael')
import aes as py_aes
import time
import unittest
import random
 

# Load the shared library
c_aes = ctypes.CDLL('./rijndael.so')

c_aes.aes_encrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
c_aes.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)  

c_aes.aes_decrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
c_aes.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)  


class TestAESOperations(unittest.TestCase):
    def gen_random_bytes(self):
        c_block = (ctypes.c_ubyte * 16)(*([random.randint(0, 255) for _ in range(16)]))
        copied_block = list(c_block)

        # Convert to a 2D list for the Python version
        py_block = [copied_block[i*4:(i+1)*4] for i in range(4)]
        return c_block, py_block


    def test_sub_bytes(self):
        

        # Generate a random test block
        test_block = (ctypes.c_ubyte * 16)(*([random.randint(0, 255) for _ in range(16)]))
        copied_block = list(test_block)

        # Convert to a 2D list for the Python version
        py_block = [copied_block[i*4:(i+1)*4] for i in range(4)]

        
        # Call the C function
        c_aes.sub_bytes(test_block)

        # Call the Python function
        py_aes.sub_bytes(py_block)

        # Flatten the Python block for comparison
        flat_py_block = [item for sublist in py_block for item in sublist]

        # Compare the results
        assert list(test_block) == flat_py_block, "Mismatch between C and Python implementations"

    def test_shift_rows(self):
        
        test_block = (ctypes.c_ubyte * 16)(*([random.randint(0, 255) for _ in range(16)]))
        c_block = (ctypes.c_ubyte * 16)(*test_block)
        py_block = [list(test_block[i*4:(i+1)*4]) for i in range(4)]

        # Call the C function
        c_aes.shift_rows(c_block)

        # Call the Python function
        py_aes.shift_rows(py_block)

        # Flatten the Python list for comparison
        flat_py_block = [item for sublist in py_block for item in sublist]

        # Convert both results to lists for comparison
        c_result = list(c_block)
        py_result = flat_py_block

        print("C result:", c_result)
        print("Python result:", py_result)

        # Assert that both implementations give the same result
        assert c_result == py_result, "Mismatch between C and Python implementations"
        print("Test passed: C and Python implementations produce the same output.")

    def test_mix_columns(self):
        
        test_block = (ctypes.c_ubyte * 16)(*([random.randint(0, 255) for _ in range(16)]))
        c_block = (ctypes.c_ubyte * 16)(*test_block)
        py_block = [list(test_block[i*4:(i+1)*4]) for i in range(4)]

        # Call the C function
        c_aes.mix_columns(c_block)

        # Call the Python function
        py_aes.mix_columns(py_block)

        # Flatten the Python list for comparison
        flat_py_block = [item for sublist in py_block for item in sublist]

        # Convert both results to lists for comparison
        c_result = list(c_block)
        py_result = flat_py_block

        print("C result:", c_result)
        print("Python result:", py_result)

        # Assert that both implementations give the same result
        assert c_result == py_result, "Mismatch between C and Python implementations"
        print("Test passed: C and Python implementations produce the same output.")


    def test_invert_sub_bytes(self):
        
        test_block = (ctypes.c_ubyte * 16)(*([random.randint(0, 255) for _ in range(16)]))
        c_block = (ctypes.c_ubyte * 16)(*test_block)
        py_block = [list(test_block[i*4:(i+1)*4]) for i in range(4)]

        # Call the C function
        c_aes.invert_sub_bytes(c_block)

        # Call the Python function
        py_aes.inv_sub_bytes(py_block)

        # Flatten the Python list for comparison
        flat_py_block = [item for sublist in py_block for item in sublist]

        # Convert both results to lists for comparison
        c_result = list(c_block)
        py_result = flat_py_block

        print("C result:", c_result)
        print("Python result:", py_result)

        # Assert that both implementations give the same result
        assert c_result == py_result, "Mismatch between C and Python implementations"
        print("Test passed: C and Python implementations produce the same output.")

    def test_invert_shift_rows(self):
        
        test_block = (ctypes.c_ubyte * 16)(*([random.randint(0, 255) for _ in range(16)]))
        c_block = (ctypes.c_ubyte * 16)(*test_block)
        py_block = [list(test_block[i*4:(i+1)*4]) for i in range(4)]

        # Call the C function
        c_aes.invert_shift_rows(c_block)

        # Call the Python function
        py_aes.inv_shift_rows(py_block)

        # Flatten the Python list for comparison
        flat_py_block = [item for sublist in py_block for item in sublist]

        # Convert both results to lists for comparison
        c_result = list(c_block)
        py_result = flat_py_block

        print("C result:", c_result)
        print("Python result:", py_result)

        # Assert that both implementations give the same result
        assert c_result == py_result, "Mismatch between C and Python implementations"
        print("Test passed: C and Python implementations produce the same output.")


    def test_invert_mix_columns(self):
        
        test_block = (ctypes.c_ubyte * 16)(*([random.randint(0, 255) for _ in range(16)]))
        c_block = (ctypes.c_ubyte * 16)(*test_block)
        py_block = [list(test_block[i*4:(i+1)*4]) for i in range(4)]

        # Call the C function
        c_aes.invert_mix_columns(c_block)

        # Call the Python function
        py_aes.inv_mix_columns(py_block)

        # Flatten the Python list for comparison
        flat_py_block = [item for sublist in py_block for item in sublist]

        # Convert both results to lists for comparison
        c_result = list(c_block)
        py_result = flat_py_block

        print("C result:", c_result)
        print("Python result:", py_result)

        # Assert that both implementations give the same result
        assert c_result == py_result, "Mismatch between C and Python implementations"
        print("Test passed: C and Python implementations produce the same output.")



    # Test function to compare C and Python implementations
    def test_add_round_key(self):
        # Generate random test block and key
        block = (ctypes.c_ubyte * 16)(*[random.randint(0, 255) for _ in range(16)])
        key = (ctypes.c_ubyte * 16)(*[random.randint(0, 255) for _ in range(16)])

        # Prepare Python versions of the block and key
        py_block = [list(block[i*4:(i+1)*4]) for i in range(4)]
        py_key = [list(key[i*4:(i+1)*4]) for i in range(4)]

        # Call the C function
        c_aes.add_round_key(block, key)

        # Call the Python function
        py_aes.add_round_key(py_block, py_key)

        # Flatten the Python list for comparison
        flat_py_block = [item for sublist in py_block for item in sublist]

        # Convert both results to lists for comparison
        c_result = list(block)
        py_result = flat_py_block

        print("C result:", c_result)
        print("Python result:", py_result)

        # Assert that both implementations give the same result
        assert c_result == py_result, "Mismatch between C and Python implementations"
        print("Test passed: C and Python implementations produce the same output.")


    def test_aes(self):
        key = os.urandom(16)
        plaintext = os.urandom(16)
        # Prepare input data for C function
        plaintext_c = (ctypes.c_ubyte * 16)(*plaintext)
        key_c = (ctypes.c_ubyte * 16)(*key)
        
        # Call the C function
        encrypted_c_ptr = c_aes.aes_encrypt_block(plaintext_c, key_c)
        print("encrypted_c_ptr", encrypted_c_ptr)
        aes = py_aes.AES(key)
        encrypted_py = aes.encrypt_block(plaintext)
        # Accessing the encrypted bytes correctly
        if encrypted_c_ptr:  # Make sure the pointer is not NULL
            encrypted_c_bytes = bytes([encrypted_c_ptr[i] for i in range(16)])  
            c_aes.free(encrypted_c_ptr)  
            # Compare results with Python version
            aes = py_aes.AES(key)
            encrypted_py = aes.encrypt_block(plaintext)

            assert encrypted_c_bytes == encrypted_py, "Mismatch between C and Python AES encryption outputs"
            print("Test passed: C and Python implementations produce the same output.")
        else:
            print("Memory allocation failed in C function")


    def test_decrypt_aes(self):
        key = os.urandom(16)
        plaintext = os.urandom(16)
        # Prepare input data for C function
        plaintext_c = (ctypes.c_ubyte * 16)(*plaintext)
        key_c = (ctypes.c_ubyte * 16)(*key)
        
        # Call the C function
        decrypted_c_ptr = c_aes.aes_decrypt_block(plaintext_c, key_c)
        print("decrypted_c_ptr", decrypted_c_ptr)
        aes = py_aes.AES(key)
        decrypted_py = aes.decrypt_block(plaintext)
        # Accessing the encrypted bytes correctly
        if decrypted_c_ptr:  
            decrypted_c_bytes = bytes([decrypted_c_ptr[i] for i in range(16)])  
            c_aes.free(decrypted_c_ptr) 
            # Compare the results with Python version
            aes = py_aes.AES(key)
            decrypted_py = aes.decrypt_block(plaintext)

            assert decrypted_c_bytes == decrypted_py, "Mismatch between C and Python AES encryption outputs"
            print("Test passed: C and Python implementations produce the same output.")
        else:
            print("Memory allocation failed in C function")



unittest.main()
unittest.main()
unittest.main()
