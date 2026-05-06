import os
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
DB_NAME = os.getenv("CAST_DB_NAME", "CAST")
COLLECTION_NAME = os.getenv("CAST_SQL_TELEMETRY_COLLECTION", "sql_telemetry")

_client = None
_collection = None


def get_collection():
    """
    Returns MongoDB collection handle for sql telemetry.
    Uses the same MONGODB_URI you already use in app.py.
    """
    global _client, _collection
    # If already initialized, reuse the cached collection
    if _collection is not None:
        return _collection

    if not MONGODB_URI:
        raise RuntimeError("MONGODB_URI is not set. Add it to your .env file.")
    # Connect to MongoDB and get the collection
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

#Insert a single telemetry event into MongoDB.
def insert_event(run_id, status, results):
    col = get_collection()
    col.insert_one({
        "run_id": run_id,
        "attack_type": "SQL injection",
        "timestamp": datetime.utcnow().isoformat(),
        "status": status,
        "results": results #List[str]
    })


def fetch_events(run_id):
    #Fetch all telemetry events for a given run_id.
    """
    Fetch events for a run, ordered oldest -> newest.
    """
    col = get_collection()
    return list(col.find({"run_id": run_id}, {"_id": 0}).sort("timestamp", 1))
