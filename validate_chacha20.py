from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Test vector from RFC 8439, Section 2.8.2 (the canonical example)
key = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f"
    "909192939495969798999a9b9c9d9e9f"
)
nonce = bytes.fromhex("070000004041424344454647")
associated_data = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
plaintext = (
    b"Ladies and Gentlemen of the class of '99: "
    b"If I could offer you only one tip for the future, "
    b"sunscreen would be it."
)

# Expected ciphertext + 16-byte Poly1305 tag, from RFC 8439 Section 2.8.2
expected = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2"
    "a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b"
    "1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58"
    "fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b"
    "6116"
    "1ae10b594f09e26a7e902ecbd0600691"
)

aead = ChaCha20Poly1305(key)
actual = aead.encrypt(nonce, plaintext, associated_data)

if actual == expected:
    print("✓ ChaCha20-Poly1305 test vector PASSED")
    print(f"  Plaintext length:  {len(plaintext)} bytes")
    print(f"  Ciphertext+tag:    {len(actual)} bytes")
    print(f"  Tag overhead:      {len(actual) - len(plaintext)} bytes")
else:
    print("✗ ChaCha20-Poly1305 test vector FAILED")
    print(f"  Expected ({len(expected)} bytes): {expected.hex()}")
    print(f"  Got      ({len(actual)} bytes): {actual.hex()}")
