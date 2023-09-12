# Import needed libraries and modules
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import hmac
import hashlib
import random

from values import *

# Crypto class
class Crypto:

    # Function for creating new object of class
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    # Initing class
    def __init__(self) -> None:
        self.public_key = b""
        self.shared_secret = b""
        self.private_key = b""
        self.mac_key = b""

    # Generating and saving key pair
    def generate_key_pair(self) -> None: 
        private_key = ec.generate_private_key(ec.SECP384R1(), os.urandom(PRIVATE_KEY_KEY_SIZE))
        public_key = private_key.public_key()
        self.private_key = private_key
        self.public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    # Generating MAC (message authentication code)
    def generate_mac(self, data : str) -> hex: 
        h = hmac.new(self.mac_key, data.encode(), hashlib.sha256)
        return h.hexdigest()

    # Verifying MAC
    def verify_mac(self, data : str, mac : hex) -> bool: 
        generated_mac = self.generate_mac(data)
        generated_mac = generated_mac.encode()
        return hmac.compare_digest(mac, generated_mac)

    # Encrypting message using pre-generated private key
    def aes_encrypt(self, text : bytes, key : bytes) -> bytes: 
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(PKCS7_SIZE).padder()
        padded_plaintext = padder.update(text) + padder.finalize()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return ciphertext

    # Decrypting message using pre-generated private key
    def aes_decrypt(self, ciphertext : bytes, key : bytes) -> [str, bytes]: 
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(PKCS7_SIZE).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        try:
            unpadded_data = unpadded_data.decode()
        except UnicodeDecodeError:
            pass
        return unpadded_data

    # Generating secret key for keys exchanging
    def generate_secret(self, public_key : bytes) -> None: 
        self.shared_secret = self.private_key.exchange(ec.ECDH(), public_key)    
        self.derive_key()

    # Derive private key
    def derive_key(self) -> None:
        kdf = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=PRIVATE_KEY_SIZE,
            otherinfo=self.shared_secret
        )    
        self.private_key = kdf.derive(self.shared_secret)
    
    # Generating MAC key
    def generate_mac_key(self) -> None: 
        kdf = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=MAC_KEY_SIZE,
            otherinfo=self.private_key
        )    
        self.mac_key = kdf.derive(self.private_key)
