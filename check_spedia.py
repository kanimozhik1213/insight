import pandas as pd

d = pd.read_csv("data/raw/logs_SPEDIA_annotated_en.csv", low_memory=False)
print("Users:", d.User.nunique())
print("Time range:", d.Timestamp.min(), "->", d.Timestamp.max())

for col in ["Agent_name", "Decoder_name", "Activity"]:
    print("\n", col, "(mean = fraction anomalous)")
    print(d.groupby(col).Anomaly.agg(["count", "mean"]).round(3).to_string())

u = d.groupby("User").Anomaly.agg(["count", "mean"])
print("\nUsers all-normal:", int((u["mean"] == 0).sum()),
      "| all-malicious:", int((u["mean"] == 1).sum()),
      "| mixed:", int(((u["mean"] > 0) & (u["mean"] < 1)).sum()))