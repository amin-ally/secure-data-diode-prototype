# src/crypto_utils.py
import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class CryptoUtils:
    def __init__(self):
        # INSECURE: Hardcoded for demo. Use secure exchange in prod.
        self.aes_key = b"x" * 32
        self.hmac_key = b"y" * 32

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        aesgcm = AESGCM(self.aes_key)
        nonce = os.urandom(12)
        return nonce + aesgcm.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, encrypted_data: bytes, associated_data: bytes = b"") -> bytes:
        aesgcm = AESGCM(self.aes_key)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        return aesgcm.decrypt(nonce, ciphertext, associated_data)

    def compute_hmac(self, data: bytes) -> bytes:
        return hmac.new(self.hmac_key, data, hashlib.sha256).digest()

    def verify_hmac(self, data: bytes, signature: bytes) -> bool:
        expected = self.compute_hmac(data)
        return hmac.compare_digest(expected, signature)
