# PROJ519: Authenticated Encryption for EEG Data on Application-Class ARM 

Benchmarks five AEAD algorithms (Ascon-AEAD128, ChaCha20-Poly1305,
AES-128-GCM, AES-256-GCM, AES-128-CCM) on a Raspberry Pi 5 using EEG
data from PhysioNet.

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

## Dataset

    python3 download_dataset.py

## Running

Lock the CPU governor first (resets on reboot):

    echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

Then:

    python3 check_libs.py
    python3 benchmark.py --reps 50 --out results_hwaccel.csv
    OPENSSL_armcap=0 python3 benchmark.py --reps 50 --out results_swonly.csv
    python3 security_tests.py --trials 500 --out results_security.csv
    python3 make_figures.py
    python3 compare_hw_sw.py
