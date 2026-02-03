from database import database_name
from bson import ObjectId
import time

collection_users = database_name['users']
groups_collection = database_name['groups']
report_collection = database_name['reports']

def serialize(report):
    report["_id"] = str(report["_id"])
    report["user_id"] = str(report["user_id"])
    report["experiment_id"] = str(report["experiment_id"])
    return report

def testinsert(user_id, experiment_id):
    return report_collection.insert_one({"user_id": ObjectId(user_id), "experiment_id": ObjectId(experiment_id), "generated_at": time.time()})
    

def getReportsForUser(user_id):
    return list(report_collection.find({"user_id": ObjectId(user_id)}).sort("generated_at", -1))
    

def getReportsForGroup():
    pass

