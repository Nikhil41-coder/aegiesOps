import os
from pathlib import Path
from .config import KILL_FILE


class KillSwitch:
    def __init__(self, store, path=None):
        self.store = store
        self.path = Path(path) if path is not None else KILL_FILE

    def dashboard(self):
        events = self.store.runtime_events("killswitch")
        return events[-1]["enabled"] if events else False

    def active(self):
        # Unknown environment values fail closed. Dashboard OFF cannot override file/env ON.
        return (
            self.dashboard()
            or self.path.exists()
            or os.getenv("AUTOMATION_KILL", "").lower() not in ("", "0", "false", "no")
        )

    def set(self, enabled):
        if type(enabled) is not bool:
            raise ValueError("enabled must be boolean")
        self.store.runtime("killswitch", {"enabled": enabled})
        return self.active()
