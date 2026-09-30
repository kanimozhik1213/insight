import pandas as pd

OUT = "data/processed/"
d = pd.read_parquet(OUT + "scored.parquet").sort_values(["user", "day"])
f = d[d["risk"] >= 30].copy()
f["gap"] = f.groupby("user")["day"].diff().dt.days
f["new"] = ((f["gap"].isna()) | (f["gap"] > 3)).astype(int)
f["inc_no"] = f.groupby("user")["new"].cumsum()

rows = []
for (u, n), g in f.groupby(["user", "inc_no"]):
    p = g.sort_values("risk").iloc[-1]
    rows.append({
        "user": u, "start": g["day"].min(), "end": g["day"].max(),
        "alert_days": len(g), "peak_risk": p["risk"], "peak_day": p["day"],
        "level": str(p["level"]), "trust": p["trust"], "trust_level": str(p["trust_level"]),
        "chain": p["chain_id"],
        "events": int(g[["usb_connects", "file_copies", "external_emails", "after_hours_logons"]].sum().sum()),
    })

inc = pd.DataFrame(rows)
if inc.empty:
    inc = pd.DataFrame(columns=["user", "start", "end", "alert_days", "peak_risk", "peak_day",
                                "level", "trust", "trust_level", "chain", "events"])
inc = inc.sort_values("peak_risk", ascending=False).reset_index(drop=True)
inc.insert(0, "incident_id", [f"INC-{i + 1:04d}" for i in range(len(inc))])
inc.to_parquet(OUT + "incidents.parquet")
print(f"{len(f)} alert days grouped into {len(inc)} incidents")
print(inc.head(10).to_string(index=False))