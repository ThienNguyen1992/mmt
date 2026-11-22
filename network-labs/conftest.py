import sys
from pathlib import Path

LABS_DIR = Path(__file__).resolve().parent
SHARED_DIR = LABS_DIR.parent / "openguard-shared"

for p in (LABS_DIR, SHARED_DIR):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))
