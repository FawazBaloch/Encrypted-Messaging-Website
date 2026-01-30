# crypto_utils.py – FINAL VERSION
#
# Backend now performs ONLY:
#   ✔ RSA keypair generation
#   ✔ Encrypting the private key using AES-GCM (password protected)
#
# Backend DOES NOT encrypt chat messages. The browser handles all AES + RSA
# to ensure compatibility and prevent decryption failures.

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64


# ============================================================
# RSA KEY GENERATION
# ============================================================

def generate_rsa_keypair():
    """
    Generates a fresh 2048-bit RSA keypair.
    Returns tuple: (public_key_pem, private_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # Export as PEM for browser compatibility
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return public_pem, private_pem


# ============================================================
# PRIVATE KEY ENCRYPTION 
# ============================================================
def encrypt_private_key_with_password(private_key_pem: str, password: str) -> str:
    """
    Encrypts the RSA private key using:
       - PBKDF2-HMAC-SHA256 (390,000 iterations)
       - AES-256-GCM
    This matches the decryption logic implemented in chat.js.
    Returns base64(salt + iv + ciphertext)
    """
    password_bytes = password.encode()
    # PBKDF2 salt
    salt = os.urandom(16)
    # Derive AES key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    aes_key = kdf.derive(password_bytes)
    # Encrypt private key
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, private_key_pem.encode(), None)
    # Store salt + iv + ciphertext
    encoded = base64.b64encode(salt + iv + ciphertext).decode()
    return encoded


def decrypt_private_key_with_password(encrypted_blob: str, password: str) -> str:
    """
    For reference only — browser performs the real decryption.
    Mirrors chat.js decryptPrivateKey().
    """

    raw = base64.b64decode(encrypted_blob)

    salt = raw[:16]
    iv = raw[16:28]
    ciphertext = raw[28:]

    # Derive key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000
    )
    aes_key = kdf.derive(password.encode())

    aesgcm = AESGCM(aes_key)
    plain = aesgcm.decrypt(iv, ciphertext, None)

    return plain.decode()
