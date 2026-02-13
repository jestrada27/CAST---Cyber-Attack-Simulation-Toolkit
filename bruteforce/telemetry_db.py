# bruteforce/telemetry_db.py
import os
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
DB_NAME = os.getenv("CAST_DB_NAME", "CAST")
COLLECTION_NAME = os.getenv("CAST_BF_TELEMETRY_COLLECTION", "bruteforce_telemetry")

_client = None
_collection = None


def get_collection():
    """
    Returns MongoDB collection handle for brute-force telemetry.
    Uses the same MONGODB_URI you already use in app.py.
    """
    global _client, _collection
    if _collection is not None:
        return _collection

    if not MONGODB_URI:
        raise RuntimeError("MONGODB_URI is not set. Add it to your .env file.")

    _client = MongoClient(MONGODB_URI, tlsAllowInvalidCertificates=True)
    db = _client[DB_NAME]
    _collection = db[COLLECTION_NAME]
    return _collection


def init_db():
    """
    MongoDB doesn't need schema initialization, but indexes help for queries.
    """
    col = get_collection()
    col.create_index("run_id")
    col.create_index("timestamp")


def insert_event(run_id, username, password, remote_ip, status, http_code, message, target_url=None):
    col = get_collection()
    col.insert_one({
        "run_id": run_id,
        "timestamp": datetime.utcnow().isoformat(),
        "username": username,
        "password": password,
        "remote_ip": remote_ip,
        "status": status,
        "http_code": int(http_code) if http_code is not None else 0,
        "message": message,
        "target_url": target_url,
    })


def fetch_events(run_id):
    """
    Fetch events for a run, ordered oldest -> newest.
    """
    col = get_collection()
    return list(col.find({"run_id": run_id}, {"_id": 0}).sort("timestamp", 1))
