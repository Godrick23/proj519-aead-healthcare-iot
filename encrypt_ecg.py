"""
Stage 5: End-to-end ECG encryption with both algorithms.

This script demonstrates the full pipeline:
  1. Load real ECG data from the MIT-BIH Arrhythmia Database
  2. Convert it to bytes
  3. Encrypt with ASCON-128
  4. Encrypt with ChaCha20-Poly1305
  5. Decrypt both and verify round-trip correctness
  6. Report communication overhead (Metric 4 of 5)

Dataset:
  Moody & Mark (2001), IEEE EMB Magazine, 20(3), 45-50.
  Goldberger et al. (2000), Circulation, 101(23), e215-e220.
"""

import wfdb
import os
import numpy as np
import ascon
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ============================================================
# Step 1: Load real ECG data from MIT-BIH record 100
# ============================================================
print("=" * 60)
print("Stage 5: End-to-end ECG encryption pipeline")
print("=" * 60)
print()
print("[1] Loading ECG record 100 from MIT-BIH Arrhythmia Database...")

signals, fields = wfdb.rdsamp('./mitdb/100')
sampling_freq = fields['fs']               # 360 Hz
total_samples = signals.shape[0]           # 650,000 samples (30 minutes)
total_duration_sec = total_samples / sampling_freq

print(f"    Loaded: {total_samples:,} samples at {sampling_freq} Hz")
print(f"    Duration: {total_duration_sec:.1f} seconds ({total_duration_sec/60:.1f} minutes)")
print(f"    Channels: {fields['sig_name']}")
print()

# ============================================================
# Step 2: Take a clinically meaningful 30-second segment
# (This represents about 30 BLE transmissions in real wearables,
#  which typically send packets every 1 second)
# ============================================================
print("[2] Extracting a 30-second segment for encryption...")

seconds_to_encrypt = 30
samples_to_use = seconds_to_encrypt * sampling_freq   # 30 * 360 = 10,800 samples
ecg_segment = signals[:samples_to_use, 0]             # use first channel (MLII)

# Convert the floating-point ECG samples to raw bytes for encryption.
# float32 = 4 bytes per sample, so 10,800 samples → 43,200 bytes (~42 KB)
plaintext = ecg_segment.astype(np.float32).tobytes()

print(f"    Segment: {seconds_to_encrypt} seconds = {samples_to_use:,} samples")
print(f"    Plaintext size: {len(plaintext):,} bytes ({len(plaintext)/1024:.1f} KB)")
print()

# ============================================================
# Step 3: Encrypt with ASCON-128
# ============================================================
print("[3] Encrypting with ASCON-128...")

ascon_key = os.urandom(16)        # 128-bit random key
ascon_nonce = os.urandom(16)      # 128-bit nonce
ascon_ad = b"patient_id=100;device=ECG_monitor"   # associated (authenticated) data

ascon_ct_and_tag = ascon.encrypt(
    ascon_key, ascon_nonce, ascon_ad, plaintext, variant="Ascon-128"
)

ascon_overhead = len(ascon_ct_and_tag) - len(plaintext)

print(f"    Key:        {ascon_key.hex()}")
print(f"    Nonce:      {ascon_nonce.hex()}")
print(f"    AD:         {ascon_ad.decode()}")
print(f"    Output:     {len(ascon_ct_and_tag):,} bytes")
print(f"    Overhead:   {ascon_overhead} bytes  <-- METRIC 4: Communication Overhead")
print()

# ============================================================
# Step 4: Encrypt with ChaCha20-Poly1305
# ============================================================
print("[4] Encrypting with ChaCha20-Poly1305...")

chacha_key = os.urandom(32)       # 256-bit key (ChaCha20 uses 256-bit keys)
chacha_nonce = os.urandom(12)     # 96-bit nonce (per RFC 8439)
chacha_ad = ascon_ad              # same associated data for fair comparison

chacha_aead = ChaCha20Poly1305(chacha_key)
chacha_ct_and_tag = chacha_aead.encrypt(chacha_nonce, plaintext, chacha_ad)

chacha_overhead = len(chacha_ct_and_tag) - len(plaintext)

print(f"    Key:        {chacha_key.hex()}")
print(f"    Nonce:      {chacha_nonce.hex()}")
print(f"    AD:         {chacha_ad.decode()}")
print(f"    Output:     {len(chacha_ct_and_tag):,} bytes")
print(f"    Overhead:   {chacha_overhead} bytes  <-- METRIC 4: Communication Overhead")
print()

# ============================================================
# Step 5: Decrypt both and verify round-trip correctness
# ============================================================
print("[5] Verifying round-trip correctness (decrypt and compare)...")

# ASCON decryption
ascon_recovered = ascon.decrypt(
    ascon_key, ascon_nonce, ascon_ad, ascon_ct_and_tag, variant="Ascon-128"
)
ascon_ok = ascon_recovered == plaintext

# ChaCha20-Poly1305 decryption
chacha_recovered = chacha_aead.decrypt(chacha_nonce, chacha_ct_and_tag, chacha_ad)
chacha_ok = chacha_recovered == plaintext

print(f"    ASCON-128 round-trip:        {'PASS' if ascon_ok else 'FAIL'}")
print(f"    ChaCha20-Poly1305 round-trip: {'PASS' if chacha_ok else 'FAIL'}")
print()

# ============================================================
# Step 6: Side-by-side summary (early result for Methodology chapter)
# ============================================================
print("=" * 60)
print("SUMMARY — first head-to-head numbers")
print("=" * 60)
print()
print(f"  Plaintext (real ECG):       {len(plaintext):,} bytes")
print()
print(f"  ASCON-128 ciphertext:       {len(ascon_ct_and_tag):,} bytes (overhead: {ascon_overhead} B)")
print(f"  ChaCha20-Poly1305:          {len(chacha_ct_and_tag):,} bytes (overhead: {chacha_overhead} B)")
print()
if ascon_overhead == chacha_overhead:
    print(f"  -> Both algorithms add the same {ascon_overhead}-byte authentication tag.")
    print(f"     Communication overhead (Metric 4) is therefore IDENTICAL between them")
    print(f"     when measured purely at the AEAD layer.")
else:
    print(f"  -> Difference in overhead: {abs(ascon_overhead - chacha_overhead)} bytes")
print()
print("  Note: Metrics 1, 2, 3, and 5 (latency, CPU, RAM, energy) require")
print("        the proper measurement harness, which is the Week 2 task.")
print()
