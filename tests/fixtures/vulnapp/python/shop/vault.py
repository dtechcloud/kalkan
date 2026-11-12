"""Card token storage of the vulnapp shop service."""

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CARD_KEY = bytes.fromhex(os.environ.get("VULNAPP_CARD_KEY", ""))


def seal_card_number(number):
    encryptor = Cipher(algorithms.AES(CARD_KEY), modes.ECB()).encryptor()
    padded = number.encode("ascii").ljust(32, b"\0")
    return encryptor.update(padded) + encryptor.finalize()


def seal_card_number_v2(number):
    nonce = os.urandom(12)
    return nonce + AESGCM(CARD_KEY).encrypt(nonce, number.encode("ascii"), None)
