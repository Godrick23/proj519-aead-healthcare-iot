import time, os, ascon
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

data = os.urandom(19200)          # matches your 30-second EEG segment
key16, key32 = os.urandom(16), os.urandom(32)
n16, n12 = os.urandom(16), os.urandom(12)

t = time.perf_counter()
ascon.encrypt(key16, n16, b"ad", data, variant="Ascon-128")
a = time.perf_counter() - t

c = ChaCha20Poly1305(key32)
t = time.perf_counter()
c.encrypt(n12, data, b"ad")
b = time.perf_counter() - t

print(f"ASCON-128 (pyascon, pure Python):  {a*1000:9.2f} ms")
print(f"ChaCha20-Poly1305 (OpenSSL C):     {b*1000:9.2f} ms")
print(f"Ratio: {a/b:.0f}x")
