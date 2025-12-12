# encrypt.py
import os
import json
import base64
from typing import Tuple
from PIL import Image

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ---------------- RSA KEY FUNCTIONS ----------------

def generate_rsa_keypair(key_size: int = 2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()
    return priv, pub

def save_private_key(private_key, path: str, password: bytes = None):
    enc = serialization.NoEncryption()
    if password:
        enc = serialization.BestAvailableEncryption(password)

    data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )
    with open(path, "wb") as f:
        f.write(data)

def save_public_key(public_key, path: str):
    data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(path, "wb") as f:
        f.write(data)

def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key(path: str, password: bytes = None):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)

def rsa_encrypt_key(public_key, key_bytes: bytes) -> str:
    encrypted = public_key.encrypt(
        key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def rsa_decrypt_key(private_key, enc_key_b64: str) -> bytes:
    encrypted = base64.b64decode(enc_key_b64)
    key = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return key

# ---------------- AES FUNCTIONS ----------------

def aes_encrypt(message: str):
    key = os.urandom(32)  # AES-256
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, message.encode("utf-8"), None)
    return key, nonce, ciphertext

def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")

# ---------------- LSB STEGANOGRAPHY ----------------

def _to_bits(data: bytes):
    bits = []
    for b in data:
        bits.extend([(b >> bit) & 1 for bit in range(7, -1, -1)])
    return bits

def _from_bits(bits):
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in range(8):
            byte = (byte << 1) | bits[i + bit]
        result.append(byte)
    return bytes(result)

def lsb_encode(in_path: str, out_path: str, payload: str):
    img = Image.open(in_path).convert("RGBA")
    pixels = list(img.getdata())

    data = payload.encode("utf-8")
    length = len(data)
    header = length.to_bytes(4, "big")

    full = header + data
    bits = _to_bits(full)

    capacity = len(pixels) * 4
    if len(bits) > capacity:
        raise ValueError("Message too large for this image")

    new_pixels = []
    bit_i = 0

    for r, g, b, a in pixels:
        chans = [r, g, b, a]
        new_chans = []
        for c in chans:
            if bit_i < len(bits):
                c = (c & ~1) | bits[bit_i]
                bit_i += 1
            new_chans.append(c)
        new_pixels.append(tuple(new_chans))

    img.putdata(new_pixels)
    img.save(out_path, "PNG")

def lsb_decode(path: str) -> str:
    img = Image.open(path).convert("RGBA")
    pixels = list(img.getdata())

    bits = []
    for px in pixels:
        for c in px:
            bits.append(c & 1)

    header_bits = bits[:32]
    header = _from_bits(header_bits)
    length = int.from_bytes(header, "big")

    msg_bits = bits[32:32 + (length * 8)]
    msg = _from_bits(msg_bits)
    return msg.decode("utf-8")

# ---------------- HYBRID RSA + AES ENCRYPTION ----------------

def hybrid_encrypt(message: str, public_key):
    aes_key, nonce, ciphertext = aes_encrypt(message)

    enc_key_b64 = rsa_encrypt_key(public_key, aes_key)
    nonce_b64 = base64.b64encode(nonce).decode()
    ct_b64 = base64.b64encode(ciphertext).decode()

    json_payload = {
        "enc_key": enc_key_b64,
        "nonce": nonce_b64,
        "ciphertext": ct_b64
    }
    return json.dumps(json_payload)

def hybrid_decrypt(json_payload: str, private_key):
    data = json.loads(json_payload)

    aes_key = rsa_decrypt_key(private_key, data["enc_key"])
    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["ciphertext"])

    return aes_decrypt(aes_key, nonce, ciphertext)

# ---------------- PUBLIC API CALLED BY APP.PY ----------------

def embed_message_rsa(in_img, out_img, message, public_key):
    json_data = hybrid_encrypt(message, public_key)
    lsb_encode(in_img, out_img, json_data)

def extract_message_rsa(encoded_img, private_key):
    json_data = lsb_decode(encoded_img)
    return hybrid_decrypt(json_data, private_key)
