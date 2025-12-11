from base64 import b64encode, b64decode
from typing import Optional, Tuple
import os
import pyotp

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import constant_time


def _b64e(b: bytes) -> str:
    return b64encode(b).decode("utf-8")


def _b64d(s: str) -> bytes:
    return b64decode(s.encode("utf-8"))


def generate_key(length: int = 32) -> bytes:
    return os.urandom(length)


def derive_key_from_password(password: str, salt: Optional[bytes] = None, length: int = 32, n: int = 2**14, r: int = 8, p: int = 1) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
    key = kdf.derive(password.encode("utf-8"))
    return key, salt


def encrypt_aes_gcm(plaintext: bytes, key: bytes, aad: Optional[bytes] = None) -> dict:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return {
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ct),
        "aad": _b64e(aad) if aad else "",
    }


def decrypt_aes_gcm(nonce_b64: str, ciphertext_b64: str, key: bytes, aad_b64: str = "") -> bytes:
    nonce = _b64d(nonce_b64)
    ct = _b64d(ciphertext_b64)
    aad = _b64d(aad_b64) if aad_b64 else None
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad)


def hash_password(password: str) -> str:
    key, salt = derive_key_from_password(password)
    return f"scrypt$_{_b64e(salt)}$_{_b64e(key)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, key_b64 = stored.split("$_")
        if not scheme.startswith("scrypt$"):
            return False
        salt = _b64d(salt_b64)
        expected = _b64d(key_b64)
        kdf = Scrypt(salt=salt, length=len(expected), n=2**14, r=8, p=1)
        derived = kdf.derive(password.encode("utf-8"))
        return constant_time.bytes_eq(derived, expected)
    except Exception:
        return False


# Added verify_google_auth_code function to verify Google Authenticator codes
def verify_google_auth_code(secret: str, code: str) -> bool:
    """
    Verify a Google Authenticator code using the shared secret.

    Args:
        secret (str): The shared secret key.
        code (str): The code to verify.

    Returns:
        bool: True if the code is valid, False otherwise.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code)
