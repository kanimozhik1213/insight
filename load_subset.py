import os, sys, re, random
sys.path.insert(0, "src")
import pandas as pd
from privacy import hash_user

# --- folder detection: files may be in data/raw or data/raw/r4.2 ---
RAW = "data/raw/r4.2/" if os.path.exists("data/raw/r4.2/logon.csv") else "data/raw/"
OUT = "data/processed/"
N_NORMAL = 300            # None = all normal users
DATE_FMT = "%m/%d/%Y %H:%M:%S"
CHUNK = 500_000
random.seed(42)

# keyword lists (check_domains.py output vechu confirm pannadhu)
JOB = ["monster", "careerbuilder", "indeed", "linkedin", "simplyhired",
       "jobhuntersbible", "job-hunt"]
COMPETITOR = ["lockheedmartin", "boeing", "raytheon", "northropgrumman",
              "harris.com", "hp.com"]
KEYLOG = ["keylog", "refog", "spectorsoft", "webwatcher", "softactivity",
          "relytec", "actionalert", "spy-soft"]
CLOUD = ["dropbox", "drive.google", "box.com", "onedrive", "mediafire",
         "4shared", "sendspace"]


def contains_any(dom, keys):
    """substring match (job, keylog, cloud)"""
    return dom.str.contains("|".join(re.escape(k) for k in keys), na=False)


def domain_is(dom, keys):
    """domain start-la or subdomain-a match aaganum (hp.com vs shp.com)"""
    pat = r"(?:^|\.)(?:" + "|".join(re.escape(k) for k in keys) + ")"
    return dom.str.contains(pat, na=False)


# 1. insiders = master list
ins = pd.read_csv("data/raw/answers/insiders.csv")
ins = ins[ins["dataset"].astype(str) == "4.2"]
bad = set(ins["user"])
print("Insiders:", len(bad))

# 2. all users, then sample normal users
users = set()
for ch in pd.read_csv(RAW + "logon.csv", usecols=["user"], chunksize=CHUNK):
    users |= set(ch["user"].unique())
pool = sorted(users - bad)
normal = pool if N_NORMAL is None else random.sample(pool, min(N_NORMAL, len(pool)))
keep = bad | set(normal)
print("Users kept:", len(keep), "(insiders:", len(bad & users), ")")


def http_post(ch):
    dom = ch["url"].str.extract(r"^(?:https?://)?(?:www\.)?([^/:?#]+)",
                                expand=False).str.lower()
    ch["domain"] = dom
    ch["is_job"] = contains_any(dom, JOB)
    ch["is_competitor"] = domain_is(dom, COMPETITOR)
    ch["is_wikileaks"] = dom.str.contains("wikileaks", na=False)
    ch["is_keylog"] = contains_any(dom, KEYLOG)
    ch["is_cloud"] = contains_any(dom, CLOUD)
    return ch.drop(columns=["url"])


def run(name, csv, cols, post=None):
    parts = []
    for i, ch in enumerate(pd.read_csv(RAW + csv, usecols=cols, chunksize=CHUNK)):
        ch = ch[ch["user"].isin(keep)].copy()
        if not ch.empty:
            ch["date"] = pd.to_datetime(ch["date"], format=DATE_FMT)
            ch["user"] = ch["user"].map(hash_user)   # labels-oda same hash
            if post:
                ch = post(ch)
            parts.append(ch)
        if name == "http" and i % 20 == 0:
            print("  http chunk", i)
    df = pd.concat(parts, ignore_index=True)
    df.to_parquet(OUT + name + ".parquet")
    print(name, len(df))


run("logon",  "logon.csv",  ["date", "user", "pc", "activity"])
run("device", "device.csv", ["date", "user", "pc", "activity"])
run("file",   "file.csv",   ["date", "user", "pc", "filename"])
run("email",  "email.csv",  ["date", "user", "to", "size", "attachments"])
# http.csv romba periya file, so last-la run aagum (20-40+ min aagalam)
run("http",   "http.csv",   ["date", "user", "pc", "url"], post=http_post)
print("Done")