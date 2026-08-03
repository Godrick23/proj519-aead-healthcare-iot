"""
Generate figures from benchmark and security results.

Produces publication-quality PNGs at 300 dpi for the results chapter.
Reads any number of benchmark CSVs so Pi 4 and Pi 5 data can be
compared once both exist.
"""
import argparse, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

plt.rcParams.update({
    "font.size": 10, "axes.grid": True, "grid.alpha": 0.3,
    "figure.dpi": 300, "savefig.bbox": "tight",
})

ORDER = ["Ascon-AEAD128", "ChaCha20-Poly1305", "AES-128-GCM",
         "AES-256-GCM", "AES-128-CCM"]
COLORS = dict(zip(ORDER, ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd"]))


def fig_latency(df, outdir):
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    for ax, col, title in [(axes[0], "enc_median_ms", "Encryption"),
                           (axes[1], "dec_median_ms", "Decryption")]:
        for algo in ORDER:
            s = df[df.algorithm == algo].sort_values("payload_bytes")
            if s.empty:
                continue
            ax.plot(s.payload_bytes, s[col], marker="o", ms=4,
                    label=algo, color=COLORS[algo])
        ax.set_xscale("log", base=2); ax.set_yscale("log")
        ax.set_xlabel("Payload size (bytes)")
        ax.set_ylabel("Median latency (ms)")
        ax.set_title(title)
    axes[0].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "fig_latency.png"))
    plt.close(fig)


def fig_throughput(df, outdir):
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for algo in ORDER:
        s = df[df.algorithm == algo].sort_values("payload_bytes")
        if s.empty:
            continue
        ax.plot(s.payload_bytes, s.enc_throughput_mbs, marker="o", ms=4,
                label=algo, color=COLORS[algo])
    ax.set_xscale("log", base=2)
    ax.set_xticks(sorted(df.payload_bytes.unique()))
    ax.set_xticklabels([str(int(v)) for v in sorted(df.payload_bytes.unique())])
    ax.minorticks_off()
    ax.set_xlabel("Payload size (bytes)")
    ax.set_ylabel("Encryption throughput (MB/s)")
    ax.set_title("Throughput scaling with payload size")
    ax.legend(fontsize=8)
    fig.savefig(os.path.join(outdir, "fig_throughput.png"))
    plt.close(fig)


def fig_largest(df, outdir):
    big = df.payload_bytes.max()
    s = df[df.payload_bytes == big].set_index("algorithm").reindex(ORDER).dropna()
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.barh(range(len(s)), s.enc_throughput_mbs,
            color=[COLORS[a] for a in s.index])
    ax.set_yticks(range(len(s))); ax.set_yticklabels(s.index)
    ax.invert_yaxis()
    ax.set_xlabel("Encryption throughput (MB/s)")
    ax.set_title("Throughput at %d-byte payload" % big)
    ax.set_xlim(0, s.enc_throughput_mbs.max() * 1.12)
    for i, v in enumerate(s.enc_throughput_mbs):
        ax.text(v, i, " %.0f" % v, va="center", fontsize=8)
    fig.savefig(os.path.join(outdir, "fig_throughput_largest.png"))
    plt.close(fig)


def fig_overhead(df, outdir):
    s = df.groupby("algorithm").first().reindex(ORDER).dropna()
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(range(len(s)), s.nonce_bytes, label="Nonce",
           color="#8c8c8c")
    ax.bar(range(len(s)), [16] * len(s), bottom=s.nonce_bytes,
           label="Tag", color="#4c72b0")
    ax.set_xticks(range(len(s)))
    ax.set_xticklabels(s.index, rotation=20, ha="right")
    ax.set_ylabel("Wire overhead (bytes)")
    ax.set_title("Per-message transmission overhead")
    ax.legend(fontsize=8)
    fig.savefig(os.path.join(outdir, "fig_overhead.png"))
    plt.close(fig)


def fig_avalanche(sec, outdir):
    s = sec.set_index("algorithm").reindex(ORDER).dropna()
    x = range(len(s)); w = 0.38
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    ax.bar([i - w/2 for i in x], s.tag_avalanche_plaintext_pct, w,
           yerr=s.tag_avalanche_plaintext_sd, capsize=3,
           label="Plaintext bit flip", color="#4c72b0")
    ax.bar([i + w/2 for i in x], s.tag_avalanche_key_pct, w,
           yerr=s.tag_avalanche_key_sd, capsize=3,
           label="Key bit flip", color="#dd8452")
    ax.axhline(50, ls="--", c="k", lw=1, label="Ideal (50%)")
    ax.set_xticks(list(x)); ax.set_xticklabels(s.index, rotation=20, ha="right")
    ax.set_ylabel("Tag bits changed (%)"); ax.set_ylim(0, 70)
    ax.set_title("Avalanche effect on authentication tag")
    ax.legend(fontsize=8)
    fig.savefig(os.path.join(outdir, "fig_avalanche.png"))
    plt.close(fig)


def main(a):
    os.makedirs(a.outdir, exist_ok=True)
    df = pd.concat([pd.read_csv(f) for f in a.benchmark], ignore_index=True)
    df = df.groupby(["algorithm", "payload_bytes"], as_index=False).median(
        numeric_only=True)
    print("Benchmark rows: %d" % len(df))

    fig_latency(df, a.outdir)
    fig_throughput(df, a.outdir)
    fig_largest(df, a.outdir)
    fig_overhead(df, a.outdir)
    if a.security:
        fig_avalanche(pd.read_csv(a.security), a.outdir)

    for f in sorted(os.listdir(a.outdir)):
        print("  " + os.path.join(a.outdir, f))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--benchmark", nargs="+",
                   default=["results_pi5_perf.csv", "results_pi5_perf_run2.csv"])
    p.add_argument("--security", default="results_security_pi5.csv")
    p.add_argument("--outdir", default="figures")
    main(p.parse_args())
