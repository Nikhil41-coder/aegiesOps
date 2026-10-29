import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Load local .env if present without requiring extra dependencies
_env_path = ROOT / ".env"
if _env_path.exists():
    try:
        with open(_env_path, encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if not _line or _line.startswith("#") or "=" not in _line:
                    continue
                _k, _v = _line.split("=", 1)
                _k = _k.strip()
                _v = _v.strip().strip("'\"")
                if _k not in os.environ:
                    os.environ[_k] = _v
    except Exception:
        pass

DATA = ROOT / "data"
DATABASE_URL = os.getenv("AEGISOPS_DATABASE_URL", f"sqlite:///{ROOT / 'aegisops.db'}")
MODE = os.getenv("AEGISOPS_MODE", "simulate")
KILL_FILE = Path(os.getenv("AEGISOPS_KILL_FILE", "/etc/automation/KILL"))
COPILOT_DB_PATH = Path(os.getenv("AEGISOPS_COPILOT_DB_PATH", DATA / "copilot_knowledge.db"))
SOURCE_CSV_DIR = Path(os.getenv("AEGISOPS_SOURCE_CSV_DIR", DATA / "source_csv"))
CHROMA_DIR = Path(os.getenv("AEGISOPS_CHROMA_DIR", DATA / "chroma_db"))
EMBEDDING_PROVIDER = os.getenv("AEGISOPS_EMBEDDING_PROVIDER", "default")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
