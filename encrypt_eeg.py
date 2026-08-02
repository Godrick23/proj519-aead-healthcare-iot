"""
Stage 5: End-to-end EEG encryption with both algorithms.

This script demonstrates the full pipeline:
  1. Load real EEG data (PhysioNet EEG Motor Movement/Imagery Dataset)
  2. Convert it to bytes
  3. Encrypt with ASCON-128
  4. Encrypt with ChaCha20-Poly1305
  5. Decrypt both and verify round-trip correctness
  6. Report communication overhead (Metric 4 of 5)

Dataset:
  Schalk, G., McFarland, D.J., Hinterberger, T., Birbaumer, N., Wolpaw, J.R. (2004).
  BCI2000: A General-Purpose Brain-Computer Interface System. IEEE TBME, 51(6), 1034-1043.
  Goldberger et al. (2000), Circulation, 101(23), e215-e220.
"""

import pandas as pd
import os
import numpy as np
import ascon
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ============================================================
# Step 1: Load real EEG data (PhysioNet EEGMMIDB, subject S001, run 01)
# ============================================================
print("=" * 60)
print("Stage 5: End-to-end EEG encryption pipeline")
print("=" * 60)
print()
print("[1] Loading EEG recording (subject S001, run 01)...")

eeg_df = pd.read_csv('./eeg_dataset/S001R01.csv')
sampling_freq = 160                          # Hz, per PhysioNet EEGMMIDB documentation
total_samples = len(eeg_df)
total_duration_sec = total_samples / sampling_freq

print(f"   Loaded: {total_samples:,} samples at {sampling_freq} Hz")
print(f"   Duration: {total_duration_sec:.1f} seconds")
print(f"   Channels: {list(eeg_df.columns[1:])}")
print()

# ============================================================
# Step 2: Take a clinically meaningful 30-second segment
# (This represents about 30 BLE transmissions in real wearables,
#  which typically send packets every 1 second)
# ============================================================
print("[2] Extracting a 30-second segment for encryption...")

seconds_to_encrypt = 30
samples_to_use = seconds_to_encrypt * sampling_freq    # 30 * 160 = 4,800 samples

if samples_to_use > total_samples:
    raise ValueError(f"Requested {samples_to_use} samples but file only has {total_samples}.")

eeg_segment = eeg_df.iloc[:samples_to_use, 1].to_numpy()   # use first EEG channel

# Convert the floating-point EEG samples to raw bytes for encryption.
# float32 = 4 bytes per sample, so 4,800 samples -> 19,200 bytes (~18.8 KB)
plaintext = eeg_segment.astype(np.float32).tobytes()

print(f"   Segment: {seconds_to_encrypt} seconds = {samples_to_use:,} samples")
print(f"   Plaintext size: {len(plaintext):,} bytes ({len(plaintext)/1024:.1f} KB)")
print()
