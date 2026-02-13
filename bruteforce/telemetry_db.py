# cast/modules/bruteforce/telemetry_db.py
import sqlite3
from datetime import datetime
from contextlib import closing
import os

DB_PATH = os.environ.get("CAST_BF_TELEMETRY_DB", "./bruteforce_telemetry.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    timestamp TEXT,
    username TEXT,
    password TEXT,
    remote_ip TEXT,
    status TEXT,
    http_code INTEGER,
    message TEXT
);
"""

def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(SCHEMA)
        conn.commit()

def insert_event(run_id, username, password, remote_ip, status, http_code, message):
    ts = datetime.utcnow().isoformat()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO telemetry (run_id, timestamp, username, password, remote_ip, status, http_code, message) VALUES (?,?,?,?,?,?,?,?)",
            (run_id, ts, username, password, remote_ip, status, http_code, message)
        )
        conn.commit()
