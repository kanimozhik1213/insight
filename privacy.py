import hashlib
import pandas as pd

# Idha maathi vechukalam. Team-kulla mattum theriyanum, GitHub-la podaadheenga.
SALT = "insight360-hackathon-2026"


def hash_user(u) -> str:
    """Raw user ID (AAF0535) -> stable pseudonym (U-1a2b3c)."""
    h = hashlib.sha256((SALT + str(u)).encode()).hexdigest()[:6]
    return "U-" + h


def hash_series(s: pd.Series) -> pd.Series:
    return s.map(hash_user)