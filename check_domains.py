import csv, glob, collections, re

c = collections.Counter()
for f in glob.glob("data/raw/answers/r4.2-*/*.csv"):
    with open(f, newline="", encoding="utf-8", errors="ignore") as fh:
        for r in csv.reader(fh):
            if r and r[0] == "http" and len(r) > 5:
                m = re.match(r"^(?:https?://)?(?:www\.)?([^/:?#]+)", r[5])
                if m:
                    c[m.group(1).lower()] += 1
for d, n in c.most_common(30):
    print(n, d)