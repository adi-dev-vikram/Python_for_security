import argparse
import os
import sys
import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import zlib
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

backend = default_backend()
iterations = 100_000

def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))

def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)


def main():
    if len(sys.argv) < 3:
        print('Invalid arguments. Please specify correct args.')
        sys.exit()


    # Create the parser
    my_parser = argparse.ArgumentParser(description='Path for file path')

    # Add the arguments
    my_parser.add_argument('--filepath',
                        metavar='path',
                        type=str,
                        help='the path to file')

    my_parser.add_argument('--key',
                        metavar='key',
                        type=str,
                        help='the key supplied')

    my_parser.add_argument('--keyid',
                        metavar='keyid',
                        type=str,
                        help='the key id supplied')



    # Execute the parse_args() method
    args = my_parser.parse_args()

    input_path = args.filepath

    input_key = args.key

    if len(str(input_key)) < 12 :
        print('Please enter longer key value')
        sys.exit()
    
    input_id = args.keyid
    
    print(input_path)
    #file_name=input_path.split('/')[-1]

    with open(input_path) as f:
        contents = f.readlines()
        for pass_elements in contents:
            message = pass_elements.split('=')[1]
            password = input_key
            storage_id = str(input_id) + "_" + pass_elements.split('=')[0][0]
            password= password_encrypt(message.encode(), password)
            os.system("security add-generic-password -a {} -w {}  -s {}".format(storage_id, password.decode("utf-8"), "python_app"))

    #token = '1'
    #password_decrypt(token, password).decode()

if __name__ == "__main__":
    main()
