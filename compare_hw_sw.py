"""Compare algorithm performance with and without hardware AES."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

plt.rcParams.update({"font.size": 10, "axes.grid": True, "grid.alpha": 0.3,
                     "figure.dpi": 300, "savefig.bbox": "tight"})

ORDER = ["Ascon-AEAD128", "ChaCha20-Poly1305", "AES-128-GCM",
         "AES-256-GCM", "AES-128-CCM"]

hw = pd.read_csv("results_pi5_hwaccel.csv")
sw = pd.read_csv("results_pi5_swonly.csv")
big = hw.payload_bytes.max()
h = hw[hw.payload_bytes == big].set_index("algorithm").reindex(ORDER)
s = sw[sw.payload_bytes == big].set_index("algorithm").reindex(ORDER)

x = range(len(ORDER)); w = 0.38
fig, ax = plt.subplots(figsize=(8, 4.8))
ax.bar([i - w/2 for i in x], h.enc_throughput_mbs, w,
       label="Hardware AES enabled", color="#4c72b0")
ax.bar([i + w/2 for i in x], s.enc_throughput_mbs, w,
       label="Software only", color="#c44e52")
for i in x:
    ax.text(i - w/2, h.enc_throughput_mbs.iloc[i], "%.0f" % h.enc_throughput_mbs.iloc[i],
            ha="center", va="bottom", fontsize=8)
    ax.text(i + w/2, s.enc_throughput_mbs.iloc[i], "%.0f" % s.enc_throughput_mbs.iloc[i],
            ha="center", va="bottom", fontsize=8)
ax.set_xticks(list(x)); ax.set_xticklabels(ORDER, rotation=20, ha="right")
ax.set_ylabel("Encryption throughput (MB/s)")
ax.set_title("Effect of ARMv8 crypto extensions (%d-byte payload)" % big)
ax.legend(fontsize=9)
fig.savefig("figures/fig_hw_vs_sw.png")
plt.close(fig)

print("%-20s %10s %10s %8s" % ("Algorithm", "HW MB/s", "SW MB/s", "Change"))
print("-" * 52)
for a in ORDER:
    hv, sv = h.loc[a, "enc_throughput_mbs"], s.loc[a, "enc_throughput_mbs"]
    print("%-20s %10.1f %10.1f %7.0f%%" % (a, hv, sv, 100 * (sv - hv) / hv))
print("\nfigures/fig_hw_vs_sw.png written")
