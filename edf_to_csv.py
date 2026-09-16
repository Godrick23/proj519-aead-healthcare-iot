"""
edf_to_csv.py
Converts PhysioNet EEG (.edf) files into CSV format for use in
the encryption/benchmarking pipeline.

Run this from inside the ~/eeg_data folder, after downloading
one or more .edf files there.
"""

import mne
import pandas as pd
import os

# ---- SETTINGS: adjust these ----
EDF_FILE = "S001R02.edf"      # the file you downloaded
OUTPUT_CSV = "S001R02.csv"    # name for the converted file
CHANNELS_TO_KEEP = ["Fc5.", "Fc3.", "Fc1.", "Fcz."]  # pick 2-4 channels only
# (Run print(raw.ch_names) once to see exact channel names available —
# PhysioNet EDF files sometimes have a trailing dot in the name.)


def convert_edf_to_csv(edf_path, output_path, channels=None):
    if not os.path.exists(edf_path):
        raise FileNotFoundError(f"Can't find {edf_path} — check it's in this folder.")

    print(f"Loading {edf_path} ...")
    raw = mne.io.read_raw_edf(edf_path, preload=True, verbose=False)

    print("Available channels:", raw.ch_names)

    if channels:
        # Only keep the channels that actually exist in this file
        valid_channels = [c for c in channels if c in raw.ch_names]
        if not valid_channels:
            print("None of the requested channels were found — using first 4 instead.")
            valid_channels = raw.ch_names[:4]
        raw.pick(valid_channels)

    data, times = raw.get_data(return_times=True)

    df = pd.DataFrame(data.T, columns=raw.ch_names)
    df.insert(0, "time", times)

    df.to_csv(output_path, index=False)
    print(f"Saved {len(df)} rows to {output_path}")


if __name__ == "__main__":
    convert_edf_to_csv(EDF_FILE, OUTPUT_CSV, CHANNELS_TO_KEEP)
