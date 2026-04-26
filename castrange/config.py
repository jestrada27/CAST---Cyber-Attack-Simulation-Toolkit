import os
import secrets
from threading import Lock

LEVELS = ("easy", "medium", "hard")
DEFENSE_LEVELS = ("off", "basic", "strict")


class RangeState:
    def __init__(self):
        self.level = "easy"
        self.defense_level = "off"
        self.token = secrets.token_urlsafe(32)
        self._lock = Lock()

    def get(self):
        with self._lock:
            return {"level": self.level, "defense_level": self.defense_level}

    def update(self, level=None, defense_level=None):
        with self._lock:
            if level in LEVELS:
                self.level = level
            if defense_level in DEFENSE_LEVELS:
                self.defense_level = defense_level
            return {"level": self.level, "defense_level": self.defense_level}


state = RangeState()

DB_PATH = os.environ.get("CASTRANGE_DB", "castrange.db")
TOKEN_FILE = os.environ.get("CASTRANGE_TOKEN_FILE", "castrange.token")
