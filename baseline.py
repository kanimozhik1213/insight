import pandas as pd

OUT = "data/processed/"
feat = pd.read_parquet(OUT + "features.parquet").sort_values(["user", "day"]).reset_index(drop=True)

COLS = ["logons", "after_hours_logons", "distinct_pcs",
        "usb_connects", "usb_after_hours",
        "file_copies", "file_after_hours",
        "emails", "external_emails", "attach_emails", "email_mb",
        "http_requests", "job_visits", "competitor_visits",
        "wikileaks_visits", "keylog_visits", "cloud_visits", "distinct_domains"]
COLS = [c for c in COLS if c in feat.columns]     # http illana skip
print("Baseline features:", len(COLS))

MIN_HIST, FULL_HIST, Z_FLAG = 5, 30, 4

# peer baseline (ella users oda average) = cold-start fallback
peer_mean = feat[COLS].mean()
peer_std = feat[COLS].std()

feat["history_days"] = feat.groupby("user").cumcount()
w = (feat["history_days"] / FULL_HIST).clip(upper=1)      # personal weight
feat["baseline_maturity"] = pd.cut(feat["history_days"], [-1, 6, 29, 10**6],
                                   labels=["Low", "Medium", "High"])


def past_stats(col, keep):
    s = feat[col].where(keep).groupby(feat["user"])
    mean = s.transform(lambda x: x.shift(1).expanding(min_periods=MIN_HIST).mean())
    std = s.transform(lambda x: x.shift(1).expanding(min_periods=MIN_HIST).std())
    return mean, std


# Pass 1: normal baseline -> odd naatkalai kandu pidi
z1 = pd.DataFrame(index=feat.index)
keep_all = pd.Series(True, index=feat.index)
for c in COLS:
    m, s = past_stats(c, keep_all)
    z1[c] = ((feat[c] - m.fillna(peer_mean[c])) / s.fillna(peer_std[c]).clip(lower=1))
feat["flagged_day"] = (z1.max(axis=1) >= Z_FLAG)

# Pass 2: flagged naatkal baseline-la serkaama, peer kooda blend
keep = ~feat["flagged_day"]
for c in COLS:
    m, s = past_stats(c, keep)
    mean = w * m.fillna(peer_mean[c]) + (1 - w) * peer_mean[c]
    std = w * s.fillna(peer_std[c]) + (1 - w) * peer_std[c]
    feat[c + "_base"] = mean
    feat[c + "_z"] = ((feat[c] - mean) / std.clip(lower=1)).fillna(0)

feat.to_parquet(OUT + "baseline.parquet")
print(feat["baseline_maturity"].value_counts())
print("Flagged days:", int(feat["flagged_day"].sum()),
      "of", len(feat), f"({feat['flagged_day'].mean():.1%})")