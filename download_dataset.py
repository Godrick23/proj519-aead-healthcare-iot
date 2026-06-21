import wfdb
import os

# Create a folder to hold the dataset
os.makedirs('mitdb', exist_ok=True)

# Download three patient records from the MIT-BIH Arrhythmia Database
print("Downloading MIT-BIH records 100, 101, 102...")
wfdb.dl_database('mitdb', dl_dir='./mitdb', records=['100', '101', '102'])
print("Download complete.")

# Read record 100 to confirm everything worked
signals, fields = wfdb.rdsamp('./mitdb/100')
print(f"\nRecord 100 loaded successfully:")
print(f"  Signal shape: {signals.shape}")
print(f"  Sampling frequency: {fields['fs']} Hz")
print(f"  Signal names: {fields['sig_name']}")
print(f"  Duration: {signals.shape[0] / fields['fs'] / 60:.1f} minutes")
