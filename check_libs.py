import ascon
from cryptography.hazmat.primitives.ciphers.aead import (
    ChaCha20Poly1305, AESGCM, AESCCM
)
import pandas, psutil, numpy, cryptography

print("pandas      ", pandas.__version__)
print("numpy       ", numpy.__version__)
print("psutil      ", psutil.__version__)
print("cryptography", cryptography.__version__)
print()

msg, ad = b"test message", b"associated"

for variant in ["Ascon-128", "Ascon-128a"]:
    try:
        out = ascon.encrypt(b"k"*16, b"n"*16, ad, msg, variant=variant)
        print(f"{variant:<20} OK   {len(out)} bytes")
    except Exception as e:
        print(f"{variant:<20} FAIL {e}")

checks = [
    ("ChaCha20-Poly1305", ChaCha20Poly1305(b"k"*32), b"n"*12),
    ("AES-128-GCM",       AESGCM(b"k"*16),           b"n"*12),
    ("AES-256-GCM",       AESGCM(b"k"*32),           b"n"*12),
    ("AES-128-CCM",       AESCCM(b"k"*16),           b"n"*12),
]

for name, cipher, nonce in checks:
    try:
        out = cipher.encrypt(nonce, msg, ad)
        print(f"{name:<20} OK   {len(out)} bytes")
    except Exception as e:
        print(f"{name:<20} FAIL {e}")
