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


def obscure(data: bytes) -> bytes:
    return b64e(zlib.compress(data, 9))

def unobscure(obscured: bytes) -> bytes:
    return zlib.decompress(b64d(obscured))

def decrypt(token: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(token)


key = Fernet.generate_key()  # store in a secure location
# PRINTING FOR DEMO PURPOSES ONLY, don't do this in production code
print("Key:", key.decode())


message = 'John Doe'
token = Fernet(key).encrypt(message.encode())
print(token)


token = decrypt(token, key).decode()

print(token)


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


message = 'John Doe'
password = 'mypass'
password_encrypt(message.encode(), password)
token = _
password_decrypt(token, password).decode()
'John Doe'

