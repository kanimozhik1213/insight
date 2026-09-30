import csv, glob, os
import pandas as pd

ANS = "data/raw/answers/"
OUT = "data/processed/"

# 1. Read all malicious-event files (one file per incident)
rows = []
for f in glob.glob(ANS + "r4.2-*/*.csv"):
    scen = int(os.path.basename(os.path.dirname(f)).split("-")[1])
    with open(f, newline="", encoding="utf-8", errors="ignore") as fh:
        for r in csv.reader(fh):
            if len(r) < 5:
                continue
            rows.append((r[0], r[1], r[2], r[3], scen))

ev = pd.DataFrame(rows, columns=["type", "id", "ts", "user", "scenario"])
ev["ts"] = pd.to_datetime(ev["ts"], format="%m/%d/%Y %H:%M:%S")
ev["day"] = ev["ts"].dt.normalize()

# 2. Master insider list (insiders.csv is the source of truth)
ins = pd.read_csv(ANS + "insiders.csv")
ins = ins[ins["dataset"].astype(str) == "4.2"]
insider_set = set(ins["user"])

ev["is_insider"] = ev["user"].isin(insider_set)
ev.to_csv(OUT + "malicious_events_raw.csv", index=False)

# 3. Victim / impersonated accounts (scenario 3 supervisors) kept separate
imp = ev[~ev["is_insider"]]
imp.to_csv(OUT + "impersonated_events.csv", index=False)

# 4. Labels only for real insiders
core_types = {"device", "file", "email", "logon"}
labels = (
    ev[ev["is_insider"]]
      .groupby(["user", "day", "scenario"])
      .agg(events=("id", "count"),
           types=("type", lambda s: ",".join(sorted(set(s)))))
      .reset_index()
)
labels["label_any"] = 1
labels["label_core"] = labels["types"].apply(
    lambda t: int(len(core_types & set(t.split(","))) > 0))
labels.to_csv(OUT + "labels_raw.csv", index=False)

# 5. Summary
print("Malicious events (all):", len(ev))
print("Insiders:", labels["user"].nunique())
print("Impersonated accounts:", sorted(imp["user"].unique()), "events:", len(imp))
print("Malicious user-days (any):", len(labels))
print("Core user-days (device/file/email/logon):", int(labels["label_core"].sum()))
print("\nEvents by type:\n", ev["type"].value_counts())
print("\nUser-days per scenario:\n", labels["scenario"].value_counts().sort_index())
print("\nSample:\n", labels.head(10))