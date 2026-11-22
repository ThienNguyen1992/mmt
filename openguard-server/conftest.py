import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent
SHARED_DIR = SERVER_DIR.parent / "openguard-shared"

for p in (SERVER_DIR, SHARED_DIR):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))
