import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.config import get_settings


def _get_key() -> bytes:
    settings = get_settings()
    key_hex = settings.encryption_master_key
    if len(key_hex) < 64:
        # Pad or hash to 32 bytes for AES-256
        import hashlib
        return hashlib.sha256(key_hex.encode()).digest()
    return bytes.fromhex(key_hex[:64])


def encrypt_value(plaintext: str) -> str:
    key = _get_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_value(encrypted: str) -> str:
    key = _get_key()
    raw = base64.b64decode(encrypted)
    nonce = raw[:12]
    ciphertext = raw[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()
