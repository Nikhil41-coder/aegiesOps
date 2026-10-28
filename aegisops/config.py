import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DATABASE_URL = os.getenv("AEGISOPS_DATABASE_URL", f"sqlite:///{ROOT / 'aegisops.db'}")
MODE = os.getenv("AEGISOPS_MODE", "simulate")
KILL_FILE = Path(os.getenv("AEGISOPS_KILL_FILE", "/etc/automation/KILL"))
