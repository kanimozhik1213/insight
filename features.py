import os
import pandas as pd

OUT = "data/processed/"
WORK_START, WORK_END = 8, 18        # 8 AM to 6 PM normal hours
COMPANY = "@dtaa.com"               # CERT internal email domain

logon = pd.read_parquet(OUT + "logon.parquet")
device = pd.read_parquet(OUT + "device.parquet")
files = pd.read_parquet(OUT + "file.parquet")
email = pd.read_parquet(OUT + "email.parquet")
HTTP_FILE = OUT + "http.parquet"
http = pd.read_parquet(HTTP_FILE) if os.path.exists(HTTP_FILE) else None

frames = [logon, device, files, email] + ([http] if http is not None else [])
for df in frames:
    df["day"] = df["date"].dt.normalize()


def after_hours(df):
    h = df["date"].dt.hour
    return ((h < WORK_START) | (h >= WORK_END)
            | (df["date"].dt.weekday >= 5)).astype(int)


# --- logon features ---
lg = logon[logon["activity"] == "Logon"].copy()
lg["after_hours"] = after_hours(lg)
f_logon = lg.groupby(["user", "day"]).agg(
    logons=("date", "count"),
    after_hours_logons=("after_hours", "sum"),
    first_logon_hour=("date", lambda s: s.dt.hour.min()),
    distinct_pcs=("pc", "nunique"),
)

# --- USB features ---
dv = device[device["activity"] == "Connect"].copy()
dv["after_hours"] = after_hours(dv)
f_usb = dv.groupby(["user", "day"]).agg(
    usb_connects=("date", "count"),
    usb_after_hours=("after_hours", "sum"),
)

# --- file features (files copied to removable media) ---
fl = files.copy()
fl["after_hours"] = after_hours(fl)
f_file = fl.groupby(["user", "day"]).agg(
    file_copies=("date", "count"),
    file_after_hours=("after_hours", "sum"),
)


# --- email features ---
def has_external(to):
    rec = [r.strip().lower() for r in str(to).split(";") if r.strip()]
    return int(any(not r.endswith(COMPANY) for r in rec))


email["external"] = email["to"].map(has_external)
email["has_attach"] = (pd.to_numeric(email["attachments"], errors="coerce")
                       .fillna(0) > 0).astype(int)
f_email = email.groupby(["user", "day"]).agg(
    emails=("date", "count"),
    external_emails=("external", "sum"),
    attach_emails=("has_attach", "sum"),
    email_mb=("size", lambda s: s.sum() / 1e6),
)

# --- http features (optional) ---
parts = [f_usb, f_file, f_email]
if http is not None:
    for c in ["is_job", "is_competitor", "is_wikileaks", "is_keylog", "is_cloud"]:
        http[c] = http[c].astype(int)
    f_http = http.groupby(["user", "day"]).agg(
        http_requests=("date", "count"),
        job_visits=("is_job", "sum"),
        competitor_visits=("is_competitor", "sum"),
        wikileaks_visits=("is_wikileaks", "sum"),
        keylog_visits=("is_keylog", "sum"),
        cloud_visits=("is_cloud", "sum"),
        distinct_domains=("domain", "nunique"),
    )
    parts.append(f_http)
else:
    print("http.parquet illa - http features skip aagudhu")

# --- merge ---
feat = f_logon.join(parts, how="outer")
feat["has_logon"] = feat["logons"].notna().astype(int)
feat["first_logon_hour"] = feat["first_logon_hour"].fillna(12)  # logon illa naal = midnight illa
feat = feat.fillna(0).reset_index().sort_values(["user", "day"])

feat.to_parquet(OUT + "features.parquet")
print(feat.shape)
print(feat.describe().T)