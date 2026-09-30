import pandas as pd, numpy as np
from sklearn.ensemble import IsolationForest

OUT = "data/processed/"
d = pd.read_parquet(OUT + "baseline.parquet").sort_values(["user", "day"]).reset_index(drop=True)
COLS = ["logons", "after_hours_logons", "distinct_pcs", "usb_connects",
        "file_copies", "emails", "external_emails", "attach_emails", "email_mb"]


def sc(z, cap=6):
    return z.clip(lower=0, upper=cap) / cap * 100


# 1. Personal anomaly = Isolation Forest + personal z-score
zcols = [c + "_z" for c in COLS]
iso = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
iso.fit(d[zcols])
raw = -iso.score_samples(d[zcols])
d["if_score"] = (raw - raw.min()) / (raw.max() - raw.min()) * 100
z_score = sc(d[["logons_z", "after_hours_logons_z", "distinct_pcs_z"]].max(axis=1))
d["personal_anomaly"] = 0.5 * d["if_score"] + 0.5 * z_score

# 2. Sensitive / file access risk
d["access_risk"] = sc(d[["distinct_pcs_z", "file_copies_z"]].max(axis=1))

# 3. Transfer / exfiltration risk
d["transfer_risk"] = sc(d[["usb_connects_z", "file_copies_z", "external_emails_z",
                           "attach_emails_z", "email_mb_z"]].max(axis=1))

# 4. Risk escalation chain (last 3 active days la evlo stages)
d["s_after"] = (d["after_hours_logons"] > 0).astype(int)
d["s_file"] = (d["file_copies"] > 0).astype(int)
d["s_usb"] = (d["usb_connects"] > 0).astype(int)
d["s_ext"] = (d["external_emails"] > 0).astype(int)
stages = ["s_after", "s_file", "s_usb", "s_ext"]
for s in stages:
    d[s + "_r"] = d.groupby("user")[s].transform(lambda x: x.rolling(3, min_periods=1).max())
d["chain_len"] = d[[s + "_r" for s in stages]].sum(axis=1)
d["sequence_risk"] = (d["chain_len"] - 1).clip(lower=0) / 3 * 100
d["chain_id"] = np.where(d["chain_len"] >= 3, "RC-EXF-01 (full chain)",
                 np.where(d["chain_len"] == 2, "RC-EXF-02 (partial chain)", "-"))

# 5. Peer-group deviation (indha naal ellaa users oda average-oda compare)
pz = []
for c in ["file_copies", "usb_connects", "external_emails", "email_mb", "after_hours_logons"]:
    g = d.groupby("day")[c]
    d[c + "_pz"] = ((d[c] - g.transform("mean")) / g.transform("std").fillna(1).clip(lower=1)).fillna(0)
    pz.append(c + "_pz")
d["peer_dev"] = sc(d[pz].max(axis=1))

# 6. Slow-and-low drift (last 7 active days vs munnadhi 21 days)
d["xfer_act"] = d["file_copies"] + d["external_emails"] + d["usb_connects"]
g = d.groupby("user")["xfer_act"]
recent = g.transform(lambda x: x.rolling(7, min_periods=3).mean())
older = g.transform(lambda x: x.shift(7).rolling(21, min_periods=7).mean())
older_sd = g.transform(lambda x: x.shift(7).rolling(21, min_periods=7).std())
d["drift_z"] = ((recent - older) / older_sd.fillna(1).clip(lower=1)).fillna(0)
d["drift_risk"] = sc(d["drift_z"], cap=4)

# Threat risk score
d["raw_risk"] = (0.30 * d["personal_anomaly"] + 0.20 * d["access_risk"]
                 + 0.20 * d["transfer_risk"] + 0.15 * d["sequence_risk"]
                 + 0.10 * d["peer_dev"] + 0.05 * d["drift_risk"]).round(1)
d["risk"] = d["raw_risk"]

# Critical override: file copy spike + transfer sign onnaa vandha
crit = (d["file_copies"] > 0) & (d["file_copies_z"] >= 3) & \
       ((d["usb_connects"] > 0) | (d["external_emails"] > 0))
d["override"] = crit
d.loc[crit, "risk"] = d.loc[crit, "risk"].clip(lower=90)
d["level"] = pd.cut(d["risk"], [-1, 29, 54, 74, 89, 100],
                    labels=["Normal", "Watch", "Suspicious", "High", "Critical"])

# Rules-only score (evaluation baseline)
d["rules_score"] = d[["access_risk", "transfer_risk", "sequence_risk"]].mean(axis=1)

# Alert Trust Score
maturity = (d["history_days"] / 30).clip(upper=1) * 100
completeness = np.where(d["logons"] > 0, 100, 40)
agree = (100 - (d["rules_score"] - d["if_score"]).abs()).clip(lower=0)
peer_agree = (100 - (d["peer_dev"] - z_score).abs()).clip(lower=0)
d["trust"] = (0.35 * maturity + 0.25 * completeness + 0.20 * agree + 0.20 * peer_agree).round(1)
d["trust_level"] = pd.cut(d["trust"], [-1, 49.99, 74.99, 100], labels=["Low", "Medium", "High"])

d.to_parquet(OUT + "scored.parquet")
print(d["level"].value_counts())
print(d["trust_level"].value_counts())

ins = pd.read_csv(OUT + "insiders_hashed.csv")
top = d.groupby("user")["risk"].max().sort_values(ascending=False)
print("\nTop 10 users by max risk:")
print(top.head(10))
print(f"\nInsiders in top 15: {len(set(top.head(15).index) & set(ins['user']))} / {len(ins)}")