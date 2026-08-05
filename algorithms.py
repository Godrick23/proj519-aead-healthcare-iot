"""
Uniform interface over the five AEAD algorithms under test.

Cipher objects are constructed once and reused, matching deployment
where a session key is established once and used for many messages.
Key scheduling therefore sits outside the timed region.
"""
import os
import ascon_fast
from cryptography.hazmat.primitives.ciphers.aead import (
    ChaCha20Poly1305, AESGCM, AESCCM
)


class AEADAlgorithm:
    def __init__(self, name, key_bytes, nonce_bytes, construction, factory):
        self.name = name
        self.key_bytes = key_bytes
        self.nonce_bytes = nonce_bytes
        self.construction = construction
        self._factory = factory
        self._enc = None
        self._dec = None

    def set_key(self, key):
        if len(key) != self.key_bytes:
            raise ValueError(
                f"{self.name} needs a {self.key_bytes}-byte key, got {len(key)}")
        self._enc, self._dec = self._factory(key)

    def new_key(self):
        return os.urandom(self.key_bytes)

    def new_nonce(self):
        return os.urandom(self.nonce_bytes)

    def encrypt(self, nonce, ad, plaintext):
        return self._enc(nonce, ad, plaintext)

    def decrypt(self, nonce, ad, ciphertext):
        return self._dec(nonce, ad, ciphertext)


def _ascon_factory(key):
    return (lambda nonce, ad, pt: ascon_fast.encrypt(key, nonce, ad, pt),
            lambda nonce, ad, ct: ascon_fast.decrypt(key, nonce, ad, ct))


def _crypto_factory(cls):
    """cryptography uses encrypt(nonce, data, aad); we normalise the order."""
    def factory(key):
        cipher = cls(key)
        return (lambda nonce, ad, pt: cipher.encrypt(nonce, pt, ad),
                lambda nonce, ad, ct: cipher.decrypt(nonce, ct, ad))
    return factory


ALGORITHMS = [
    AEADAlgorithm("Ascon-AEAD128",     16, 16, "sponge",
                  _ascon_factory),
    AEADAlgorithm("ChaCha20-Poly1305", 32, 12, "stream + MAC",
                  _crypto_factory(ChaCha20Poly1305)),
    AEADAlgorithm("AES-128-GCM",       16, 12, "block, CTR + GHASH",
                  _crypto_factory(AESGCM)),
    AEADAlgorithm("AES-256-GCM",       32, 12, "block, CTR + GHASH",
                  _crypto_factory(AESGCM)),
    AEADAlgorithm("AES-128-CCM",       16, 12, "block, CTR + CBC-MAC",
                  _crypto_factory(AESCCM)),
]


if __name__ == "__main__":
    msg, ad = b"EEG sample payload", b"subject=S001;channel=Fc5"
    print(f"{'Algorithm':<20} {'Key':>4} {'Nonce':>6} {'Tag':>4}  Construction")
    print("-" * 70)
    for a in ALGORITHMS:
        a.set_key(a.new_key())
        nonce = a.new_nonce()
        ct = a.encrypt(nonce, ad, msg)
        assert a.decrypt(nonce, ad, ct) == msg, f"{a.name} round trip failed"

        bad = bytearray(ct); bad[0] ^= 1
        try:
            a.decrypt(nonce, ad, bytes(bad))
            raise SystemExit(f"{a.name}: tampering NOT detected")
        except Exception:
            pass

        print(f"{a.name:<20} {a.key_bytes:>4} {a.nonce_bytes:>6} "
              f"{len(ct) - len(msg):>4}  {a.construction}")
    print("\nAll five verified: round trip and tamper detection.")
