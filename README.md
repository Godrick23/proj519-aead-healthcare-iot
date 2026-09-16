# PROJ519: Authenticated Encryption for EEG Data on Application-Class ARM

MSc Cyber Security dissertation, University of Plymouth.

Benchmarks five AEAD algorithms on a Raspberry Pi 5 using EEG data from
PhysioNet, and isolates the effect of the ARMv8 cryptographic extensions
by disabling OpenSSL's hardware detection on the same board.

| Algorithm | Construction | Standard |
|---|---|---|
| Ascon-AEAD128 | Sponge duplex | NIST SP 800-232 |
| ChaCha20-Poly1305 | Stream cipher with MAC | RFC 8439 |
| AES-128-GCM | Block, CTR with GHASH | NIST SP 800-38D |
| AES-256-GCM | Block, CTR with GHASH | NIST SP 800-38D |
| AES-128-CCM | Block, CTR with CBC-MAC | NIST SP 800-38C |

## Setup

Python 3.13 in a virtual environment:

    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

## Building the Ascon library

`ascon_fast.py` requires `libascon.so`, compiled from the official
ascon-c repository. The upstream source is not included here.

    git clone https://github.com/ascon/ascon-c.git
    cd ascon-c
    gcc -O3 -shared -fPIC \
        -I crypto_aead/asconaead128/opt64 \
        -I tests \
        crypto_aead/asconaead128/opt64/*.c \
        -o libascon.so
    cp libascon.so ..

The second include path is required because `aead.c` includes
`crypto_aead.h`, which lives in the repository's `tests/` directory.

The `opt64` implementation is used rather than `ref`. This matters: the
PyPI `ascon` package is pure Python and measured roughly 2,580 times
slower than OpenSSL-backed ChaCha20-Poly1305 on a 19,200-byte payload.
Compiling the optimised C implementation brought that ratio to 2.54. The
PyPI package also implements the superseded v1.2 specification rather
than the standardised Ascon-AEAD128.

## Dataset

    python3 download_dataset.py

The PhysioNet EEG Motor Movement/Imagery Database recordings are supplied as EDF. Conversion to the CSV format that 
the benchmark reads was done with MNE-Python and pandas: four frontal channels (Fc5, Fc3, Fc1, Fcz) at 160 Hz, serialised as float32,
giving 156,160 bytes per recording.

## Running

Lock the CPU governor first (resets on reboot):

    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

Confirm it reads `performance` and 2400000 before continuing. Then:

    python3 check_libs.py
    python3 benchmark.py --reps 50 --out results_hwaccel.csv
    OPENSSL_armcap=0 python3 benchmark.py --reps 50 --out results_swonly.csv
    python3 security_tests.py --trials 500 --out results_security.csv
    python3 make_figures.py
    python3 compare_hw_sw.py

Setting `OPENSSL_armcap=0` forces OpenSSL onto generic software paths,
disabling the AES, PMULL and NEON implementations. Everything else stays
identical, so the two runs differ in one variable. Ascon is unaffected
because it never enters OpenSSL.

## What each file does

Core pipeline:

| File | Purpose |
|---|---|
| `algorithms.py` | Gives all five algorithms one `encrypt(nonce, ad, plaintext)` signature. Cipher objects are built once, keeping key scheduling outside the timed region. |
| `ascon_fast.py` | ctypes wrapper over `libascon.so`, using the NIST/SUPERCOP `crypto_aead_encrypt` interface. |
| `benchmark.py` | Performance measurement. Captures platform details, runs warmup and timed encryption and decryption, measures memory separately, writes one CSV row per algorithm and payload size. |
| `security_tests.py` | Avalanche measurement over the authentication tag, plus four attack classes at 500 trials each. |
| `download_dataset.py` | Fetches the dataset. |

Analysis:

| File | Purpose |
|---|---|
| `make_figures.py` | Five figures at 300 dpi. Takes the median across independent runs before plotting. |
| `compare_hw_sw.py` | Hardware versus software comparison figure and change table. |

Verification:

| File | Purpose |
|---|---|
| `check_libs.py` | Confirms all five algorithms load and produce 16-byte tags. |
| `quick_timing.py` | The implementation-parity check that exposed the pure-Python Ascon problem. |
| `test_ascon_fast.py` | Round trip, tamper detection and overhead check for the Ascon wrapper. |

`encrypt_ecg.py`, `encrypt_eeg.py`, `validate_ascon.py` and
`validate_chacha20.py` are from the initial two-algorithm phase using ECG
data. They are kept for provenance and are not used in the reported results.

## Results

| File | Condition |
|---|---|
| `results_pi5_hwaccel.csv` | Hardware AES active |
| `results_pi5_swonly.csv` | `OPENSSL_armcap=0` |
| `results_pi5_perf.csv` | Hardware AES, independent run 1 |
| `results_pi5_perf_run2.csv` | Hardware AES, independent run 2 |
| `results_security_pi5.csv` | Avalanche and attack resistance, 500 trials |

The hardware-versus-software comparison uses the matched `hwaccel` and
`swonly` pair. The two `perf` runs establish reproducibility: throughput
figures agree to within 0.5%.

Each row records the board model, kernel, CPU frequency, feature flags and
the `OPENSSL_armcap` state, so datasets from different conditions stay
distinguishable.

## Headline result

Encryption throughput at a 19,200-byte payload:

| Algorithm | Hardware AES | Software only | Change |
|---|---|---|---|
| Ascon-AEAD128 | 410 MB/s | 415 MB/s | +1.2% |
| ChaCha20-Poly1305 | 653 | 286 | -56% |
| AES-128-GCM | 1979 | 105 | -95% |
| AES-256-GCM | 1656 | 89 | -95% |
| AES-128-CCM | 873 | 103 | -88% |

The ranking inverts. Ascon acts as the control: it runs through the
compiled C library rather than OpenSSL, so it should not move, and it
does not.

## Platform

Raspberry Pi 5 Model B Rev 1.0, Cortex-A76 at 2400 MHz, kernel
6.18.34+rpt-rpi-2712 (aarch64), gcc 14.2.0. CPU features include `aes`,
`pmull`, `sha1` and `sha2`.

The hostname reads `raspberrypi4`. This is a label left over from an
earlier configuration; `cat /proc/device-tree/model` confirms the board.
