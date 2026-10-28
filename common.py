"""Shared helpers: hashing, JSON/CSV I/O, and Wilson confidence intervals."""
import csv
import hashlib
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS_PATH = ROOT / "data" / "scenarios.json"
HASH_PATH = ROOT / "data" / "SCENARIOS_SHA256.txt"


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path) -> str:
    """Hash raw bytes so the value matches `sha256sum` on every OS."""
    return sha256_bytes(Path(path).read_bytes())


def sha256_text(s: str) -> str:
    return sha256_bytes(s.encode("utf-8"))


def recorded_hash(path=HASH_PATH):
    m = re.search(r"\b[0-9a-f]{64}\b", Path(path).read_text(encoding="utf-8"))
    return m.group(0) if m else None


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"File not found: {path}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"Invalid JSON in {path}: {e}")


def wilson(k: int, n: int, z: float = 1.96):
    """Wilson score interval for a proportion; None when n == 0. Better than the normal
    approximation for small n or rates near 0 or 1."""
    if n <= 0:
        return None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def rate(k: int, n: int):
    return round(k / n, 4) if n else None


_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(v):
    """Neutralise spreadsheet formula injection in model-generated text."""
    if isinstance(v, str) and v.startswith(_FORMULA):
        return "'" + v
    return v


def write_csv(path, fields, rows):
    with Path(path).open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: csv_safe(r.get(k, "")) for k in fields})
