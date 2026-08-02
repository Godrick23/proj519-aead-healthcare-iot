"""
Ascon-AEAD128 via the official optimised C implementation (ascon-c, opt64).
Wraps crypto_aead_encrypt / crypto_aead_decrypt using ctypes.
"""
import ctypes, os

_lib = ctypes.CDLL(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "libascon.so"))

KEY_BYTES, NONCE_BYTES, TAG_BYTES = 16, 16, 16

# int crypto_aead_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k)
_lib.crypto_aead_encrypt.restype = ctypes.c_int
_lib.crypto_aead_encrypt.argtypes = [
    ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.c_char_p, ctypes.c_ulonglong,
    ctypes.c_char_p, ctypes.c_ulonglong,
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
]
_lib.crypto_aead_decrypt.restype = ctypes.c_int
_lib.crypto_aead_decrypt.argtypes = [
    ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.c_char_p,
    ctypes.c_char_p, ctypes.c_ulonglong,
    ctypes.c_char_p, ctypes.c_ulonglong,
    ctypes.c_char_p, ctypes.c_char_p,
]


def encrypt(key, nonce, ad, plaintext):
    if len(key) != KEY_BYTES or len(nonce) != NONCE_BYTES:
        raise ValueError("key and nonce must both be 16 bytes")
    buf = ctypes.create_string_buffer(len(plaintext) + TAG_BYTES)
    clen = ctypes.c_ulonglong(0)
    rc = _lib.crypto_aead_encrypt(buf, ctypes.byref(clen),
                                  plaintext, len(plaintext),
                                  ad, len(ad), None, nonce, key)
    if rc != 0:
        raise RuntimeError(f"encryption failed, rc={rc}")
    return buf.raw[:clen.value]


def decrypt(key, nonce, ad, ciphertext):
    if len(ciphertext) < TAG_BYTES:
        raise ValueError("ciphertext shorter than the tag")
    buf = ctypes.create_string_buffer(len(ciphertext))
    mlen = ctypes.c_ulonglong(0)
    rc = _lib.crypto_aead_decrypt(buf, ctypes.byref(mlen), None,
                                  ciphertext, len(ciphertext),
                                  ad, len(ad), nonce, key)
    if rc != 0:
        raise RuntimeError("authentication failed")
    return buf.raw[:mlen.value]
