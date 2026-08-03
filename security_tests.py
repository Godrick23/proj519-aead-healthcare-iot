"""
Cryptographic behaviour and attack resistance tests.

Avalanche is measured over the 16-byte authentication tag. Stream-based
AEAD (ChaCha20, GCM, CCM) leaves ciphertext body bits unchanged when one
plaintext bit flips, so body diffusion is not a meaningful comparison
across constructions; the tag is what provides integrity.
"""
import argparse, csv, random, statistics
from datetime import datetime
import numpy as np
import pandas as pd
from algorithms import ALGORITHMS

AD = b"subject=S001;device=eeg-node;fmt=float32"
OTHER_AD = b"subject=S002;device=eeg-node;fmt=float32"
PAYLOAD = 1024
TAG = 16


def bit_diff_pct(a, b):
    n = min(len(a), len(b))
    x = np.frombuffer(a[:n], dtype=np.uint8) ^ np.frombuffer(b[:n], dtype=np.uint8)
    return 100.0 * np.unpackbits(x).sum() / (n * 8)


def flip_bit(data, pos):
    out = bytearray(data)
    out[pos // 8] ^= (1 << (pos % 8))
    return bytes(out)


def avalanche(algo, plaintext, trials):
    pt_res, key_res = [], []
    for _ in range(trials):
        key, nonce = algo.new_key(), algo.new_nonce()
        algo.set_key(key)
        base = algo.encrypt(nonce, AD, plaintext)

        pos = random.randrange(len(plaintext) * 8)
        mod = algo.encrypt(nonce, AD, flip_bit(plaintext, pos))
        pt_res.append(bit_diff_pct(base[-TAG:], mod[-TAG:]))

        pos = random.randrange(len(key) * 8)
        algo.set_key(flip_bit(key, pos))
        mod = algo.encrypt(nonce, AD, plaintext)
        key_res.append(bit_diff_pct(base[-TAG:], mod[-TAG:]))
    return pt_res, key_res


def attacks(algo, plaintext, trials):
    caught = {"ciphertext_tamper": 0, "tag_tamper": 0,
              "wrong_nonce": 0, "wrong_ad": 0}
    for _ in range(trials):
        key, nonce = algo.new_key(), algo.new_nonce()
        algo.set_key(key)
        ct = algo.encrypt(nonce, AD, plaintext)
        body = len(ct) - TAG
        variants = {
            "ciphertext_tamper": (nonce, AD, flip_bit(ct, random.randrange(body * 8))),
            "tag_tamper": (nonce, AD, flip_bit(ct, random.randrange(body * 8, len(ct) * 8))),
            "wrong_nonce": (algo.new_nonce(), AD, ct),
            "wrong_ad": (nonce, OTHER_AD, ct),
        }
        for name, (n, ad, c) in variants.items():
            try:
                algo.decrypt(n, ad, c)
            except Exception:
                caught[name] += 1
    return caught


def run(args):
    df = pd.read_csv(args.data)
    ch = [c for c in df.columns if c.lower() != "time"]
    pt = df[ch].to_numpy(dtype=np.float32).tobytes()[:PAYLOAD]

    rows = []
    for algo in ALGORITHMS:
        print("\n" + algo.name)
        pt_av, key_av = avalanche(algo, pt, args.trials)
        caught = attacks(algo, pt, args.trials)
        print("  tag avalanche (plaintext bit)  %6.2f %% (sd %.2f)"
              % (statistics.mean(pt_av), statistics.stdev(pt_av)))
        print("  tag avalanche (key bit)        %6.2f %% (sd %.2f)"
              % (statistics.mean(key_av), statistics.stdev(key_av)))
        for name, n in caught.items():
            flag = "" if n == args.trials else "   <-- FAILURE"
            print("  %-20s %6.1f %% caught%s" % (name, 100 * n / args.trials, flag))

        row = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "algorithm": algo.name,
            "construction": algo.construction,
            "trials": args.trials,
            "payload_bytes": PAYLOAD,
            "tag_avalanche_plaintext_pct": round(statistics.mean(pt_av), 3),
            "tag_avalanche_plaintext_sd": round(statistics.stdev(pt_av), 3),
            "tag_avalanche_key_pct": round(statistics.mean(key_av), 3),
            "tag_avalanche_key_sd": round(statistics.stdev(key_av), 3),
        }
        for k, v in caught.items():
            row[k + "_caught_pct"] = round(100 * v / args.trials, 2)
        rows.append(row)

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print("\nWrote %d rows to %s" % (len(rows), args.out))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--data", default="eeg_dataset/S001R01.csv")
    p.add_argument("--trials", type=int, default=100)
    p.add_argument("--out", default="results_security.csv")
    run(p.parse_args())
