import sqlite3
from pathlib import Path

from castrange import config

SCHEMA_PATH = Path(__file__).parent / "seed.sql"


def get_conn():
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    db_path = Path(config.DB_PATH)
    if db_path.exists():
        db_path.unlink()
    conn = get_conn()
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


def log_request(method, path, query, status, latency_ms, remote_ip,
                payload_signature=None, vuln_triggered=False, detected=False):
    conn = get_conn()
    conn.execute(
        "INSERT INTO access_log "
        "(ts, method, path, query, status, latency_ms, remote_ip, "
        " payload_signature, vuln_triggered, detected) "
        "VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (method, path, query, status, latency_ms, remote_ip,
         payload_signature, int(bool(vuln_triggered)), int(bool(detected))),
    )
    conn.commit()
    conn.close()
