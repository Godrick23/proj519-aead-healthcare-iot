import os, time, ascon_fast
import ascon as ascon_slow
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

key, nonce, ad = os.urandom(16), os.urandom(16), b"subject=S001"
data = os.urandom(19200)

ct = ascon_fast.encrypt(key, nonce, ad, data)
pt = ascon_fast.decrypt(key, nonce, ad, ct)
assert pt == data, "round trip failed"
print(f"Round trip OK. Overhead: {len(ct) - len(data)} bytes")

tampered = bytearray(ct); tampered[100] ^= 1
try:
    ascon_fast.decrypt(key, nonce, ad, bytes(tampered))
    print("PROBLEM: tampering not detected")
except RuntimeError:
    print("Tamper detection OK")

def bench(fn, n=20):
    ts = []
    for _ in range(n):
        t = time.perf_counter(); fn(); ts.append(time.perf_counter() - t)
    return sorted(ts)[n // 2] * 1000

fast = bench(lambda: ascon_fast.encrypt(key, nonce, ad, data))
slow = bench(lambda: ascon_slow.encrypt(key, nonce, ad, data,
                                        variant="Ascon-128"), n=3)
c = ChaCha20Poly1305(os.urandom(32)); n12 = os.urandom(12)
cha = bench(lambda: c.encrypt(n12, data, ad))

print(f"\nAscon-AEAD128 (opt64 C):   {fast:8.3f} ms")
print(f"ascon 0.0.9 (pure Python): {slow:8.3f} ms")
print(f"ChaCha20-Poly1305:         {cha:8.3f} ms")
print(f"\nSpeedup over pure Python: {slow/fast:.0f}x")
print(f"Ascon vs ChaCha20 ratio:  {fast/cha:.2f}x")
