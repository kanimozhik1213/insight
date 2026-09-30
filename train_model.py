import sys
sys.path.insert(0, "src")
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import GroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import (precision_score, recall_score, f1_score,
                             average_precision_score, confusion_matrix)

OUT = "data/processed/"
FEAT_FILE = OUT + "baseline.parquet"   # _z columns inga dhaan irukku
TARGET = "label_any"                   # "label_core" kooda try pannalaam
DROP = {"history_days"}                # security signal illa

feat = pd.read_parquet(FEAT_FILE)
lab = pd.read_csv(OUT + "labels.csv", parse_dates=["day"])
feat["day"] = pd.to_datetime(feat["day"])

df = feat.merge(lab[["user", "day", TARGET]], on=["user", "day"], how="left")
df[TARGET] = df[TARGET].fillna(0).astype(int)
print("Rows:", len(df), "| Positives:", int(df[TARGET].sum()))
assert df[TARGET].sum() > 0, "Labels match aagala - user ID/day format check pannunga"

cols = [c for c in df.select_dtypes("number").columns
        if c != TARGET and c not in DROP]
X = df[cols].fillna(0).values
y = df[TARGET].values
groups = df["user"].values

models = {
    "Logistic Regression": lambda: make_pipeline(
        StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=1000)),
    "Random Forest": lambda: RandomForestClassifier(
        n_estimators=200, min_samples_leaf=3, class_weight="balanced",
        n_jobs=-1, random_state=42),
}

oof = {k: np.zeros(len(df)) for k in list(models) + ["Isolation Forest"]}

# user-based split: same user rendu side-um varaadhu (leakage illa)
for tr, te in GroupKFold(n_splits=5).split(X, y, groups):
    for name, make in models.items():
        m = make().fit(X[tr], y[tr])
        oof[name][te] = m.predict_proba(X[te])[:, 1]
    iso = IsolationForest(n_estimators=200, random_state=42, n_jobs=-1).fit(X[tr])
    oof["Isolation Forest"][te] = -iso.score_samples(X[te])


def report(name, s):
    # supervised: 0.5 threshold; Isolation Forest: top 1% flag
    thr = 0.5 if name != "Isolation Forest" else np.quantile(s, 0.99)
    p = (s >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    return {"Model": name,
            "Precision": precision_score(y, p, zero_division=0),
            "Recall": recall_score(y, p),
            "F1": f1_score(y, p),
            "FPR": fp / (fp + tn),
            "FNR": fn / (fn + tp),
            "PR-AUC": average_precision_score(y, s),
            "TP": tp, "FP": fp, "FN": fn, "TN": tn}


res = pd.DataFrame([report(k, v) for k, v in oof.items()]).round(4)
print(res.to_string(index=False))
res.to_csv(OUT + "model_metrics.csv", index=False)

# final model + feature importance (dashboard + explanation-kaaga)
rf = models["Random Forest"]().fit(X, y)
joblib.dump({"model": rf, "features": cols}, "models_rf.joblib")
imp = pd.Series(rf.feature_importances_, index=cols).sort_values(ascending=False)
imp.to_csv(OUT + "feature_importance.csv")
print("\nTop features:\n", imp.head(10))