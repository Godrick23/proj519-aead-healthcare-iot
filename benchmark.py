"""
AEAD benchmark harness for EEG data on single-board ARM platforms.

Runs five AEAD algorithms across a range of payload sizes, recording
latency, throughput, memory and CPU time. Writes one CSV row per
algorithm/payload combination.

Runs unchanged on any Linux board; platform details are captured
automatically so results from different machines stay distinguishable.
"""
import argparse, csv, gc, os, platform, statistics, subprocess, sys
import time, tracemalloc
from datetime import datetime

import numpy as np
import pandas as pd
import psutil

from algorithms import ALGORITHMS

PAYLOAD_SIZES = [64, 256, 1024, 4096, 19200]
DEFAULT_REPS = 30
WARMUP_REPS = 5
ASSOCIATED_DATA = b"subject=S001;device=eeg-node;fmt=float32"


def platform_info():
    """Capture everything needed to tell one board's results from another."""
    info = {
        "hostname": platform.node(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "cores": os.cpu_count(),
    }
    try:
        with open("/proc/device-tree/model") as f:
            info["board"] = f.read().strip("\x00").strip()
    except OSError:
        info["board"] = "unknown"
    try:
        with open("/proc/cpuinfo") as f:
            feats = [l for l in f if l.startswith("Features")]
        info["cpu_features"] = feats[0].split(":", 1)[1].strip() if feats else ""
    except OSError:
        info["cpu_features"] = ""
    info["aes_hw"] = "aes" in info["cpu_features"].split()
    info["openssl_armcap"] = os.environ.get("OPENSSL_armcap", "default")
    info["hw_accel_enabled"] = info["aes_hw"] and info["openssl_armcap"] != "0"
    try:
        info["cpu_mhz"] = int(subprocess.check_output(
            ["cat", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"]
        ).strip()) // 1000
    except Exception:
        info["cpu_mhz"] = 0
    return info


def load_eeg_bytes(path, needed):
    """Read EEG channels as float32 and return at least `needed` bytes."""
    df = pd.read_csv(path)
    channels = [c for c in df.columns if c.lower() != "time"]
    raw = df[channels].to_numpy(dtype=np.float32).tobytes()
    if len(raw) < needed:
        raise ValueError(f"{path} yields {len(raw)} bytes, need {needed}")
    print(f"Loaded {path}: {len(channels)} channels, {len(raw)} bytes")
    return raw


def time_operation(fn, reps):
    """Median and IQR in ms, with total CPU time across all reps."""
    for _ in range(WARMUP_REPS):
        fn(0)
    gc.disable()
    cpu0 = time.process_time()
    samples = []
    for i in range(reps):
        t0 = time.perf_counter()
        fn(i)
        samples.append(time.perf_counter() - t0)
    cpu_total = time.process_time() - cpu0
    gc.enable()
    samples.sort()
    q1 = samples[len(samples) // 4]
    q3 = samples[(3 * len(samples)) // 4]
    return {
        "median_ms": statistics.median(samples) * 1000,
        "iqr_ms": (q3 - q1) * 1000,
        "min_ms": samples[0] * 1000,
        "max_ms": samples[-1] * 1000,
        "cpu_time_s": cpu_total,
    }


def measure_memory(algo, nonce, plaintext):
    """Python-level peak allocation plus process RSS delta, both in KB.

    tracemalloc sees only Python allocations, so C-side buffers in
    OpenSSL and ascon-c are invisible to it. RSS delta is coarser but
    catches those. Both are reported; neither alone is complete.
    """
    proc = psutil.Process()
    gc.collect()
    rss_before = proc.memory_info().rss
    tracemalloc.start()
    ct = algo.encrypt(nonce, ASSOCIATED_DATA, plaintext)
    algo.decrypt(nonce, ASSOCIATED_DATA, ct)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_after = proc.memory_info().rss
    return peak / 1024, max(0, rss_after - rss_before) / 1024


def run(args):
    info = platform_info()
    print("=" * 68)
    print(f"Board:    {info['board']}")
    print(f"Kernel:   {info['kernel']}  ({info['arch']}, {info['cores']} cores)")
    print(f"CPU freq: {info['cpu_mhz']} MHz")
    print(f"AES in hardware: {'yes' if info['aes_hw'] else 'no'}"
          f"   OpenSSL armcap: {info['openssl_armcap']}"
          f"   accel active: {info['hw_accel_enabled']}")
    print(f"Repetitions per measurement: {args.reps}")
    print("=" * 68)

    eeg = load_eeg_bytes(args.data, max(PAYLOAD_SIZES))
    rows = []

    for algo in ALGORITHMS:
        algo.set_key(algo.new_key())
        print(f"\n{algo.name}")
        for size in PAYLOAD_SIZES:
            pt = eeg[:size]
            nonces = [algo.new_nonce() for _ in range(args.reps + WARMUP_REPS)]

            ct = algo.encrypt(nonces[0], ASSOCIATED_DATA, pt)
            if algo.decrypt(nonces[0], ASSOCIATED_DATA, ct) != pt:
                sys.exit(f"FATAL: {algo.name} round trip failed at {size} B")

            enc = time_operation(
                lambda i: algo.encrypt(nonces[i], ASSOCIATED_DATA, pt),
                args.reps)

            cts = [algo.encrypt(n, ASSOCIATED_DATA, pt)
                   for n in nonces[:args.reps + WARMUP_REPS]]
            dec = time_operation(
                lambda i: algo.decrypt(nonces[i], ASSOCIATED_DATA, cts[i]),
                args.reps)

            tm_kb, rss_kb = measure_memory(algo, nonces[0], pt)
            overhead = len(ct) - size + algo.nonce_bytes

            rows.append({
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "board": info["board"],
                "hostname": info["hostname"],
                "cpu_mhz": info["cpu_mhz"],
                "aes_hw": info["aes_hw"],
                "openssl_armcap": info["openssl_armcap"],
                "hw_accel_enabled": info["hw_accel_enabled"],
                "algorithm": algo.name,
                "construction": algo.construction,
                "key_bytes": algo.key_bytes,
                "nonce_bytes": algo.nonce_bytes,
                "payload_bytes": size,
                "reps": args.reps,
                "enc_median_ms": round(enc["median_ms"], 6),
                "enc_iqr_ms": round(enc["iqr_ms"], 6),
                "enc_min_ms": round(enc["min_ms"], 6),
                "enc_max_ms": round(enc["max_ms"], 6),
                "dec_median_ms": round(dec["median_ms"], 6),
                "dec_iqr_ms": round(dec["iqr_ms"], 6),
                "enc_throughput_mbs": round(
                    size / (enc["median_ms"] / 1000) / 1e6, 4),
                "dec_throughput_mbs": round(
                    size / (dec["median_ms"] / 1000) / 1e6, 4),
                "enc_cpu_time_s": round(enc["cpu_time_s"], 6),
                "dec_cpu_time_s": round(dec["cpu_time_s"], 6),
                "tracemalloc_peak_kb": round(tm_kb, 2),
                "rss_delta_kb": round(rss_kb, 2),
                "ciphertext_bytes": len(ct),
                "overhead_bytes": overhead,
                "overhead_pct": round(100 * overhead / size, 3),
            })
            print(f"  {size:>6} B   enc {enc['median_ms']:8.4f} ms   "
                  f"dec {dec['median_ms']:8.4f} ms   "
                  f"{rows[-1]['enc_throughput_mbs']:7.2f} MB/s")

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\nWrote {len(rows)} rows to {args.out}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--data", default="eeg_dataset/S001R01.csv")
    p.add_argument("--reps", type=int, default=DEFAULT_REPS)
    p.add_argument("--out", default="results_benchmark.csv")
    run(p.parse_args())
