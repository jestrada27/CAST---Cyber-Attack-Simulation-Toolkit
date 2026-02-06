from datetime import datetime
from pymongo import MongoClient
from bson import ObjectId
import random
import os

# MongoDB connection
#MONGODB_URI = YOUR URL

client = MongoClient(MONGODB_URI, tlsAllowInvalidCertificates=True)
database_name = client["CAST"]

# Collections
collection_users = database_name["users"]
collection_attacks = database_name["attacks"]  # NEW: Store attacks here

# Attack types and statuses
attack_types = ["SQL Injection", "DDoS", "XSS", "Brute Force"]
statuses = ["Stored to Local", "In Progress", "Completed", "Failed"]

def generate_random_attack(user_id):
    attack = {
        "user_id": user_id,  # Link attack to user
        "attack_type": random.choice(attack_types),
        "timestamp": datetime.utcnow(),  # Store as datetime object
        "status": random.choice(statuses),
        "performance": random.randint(45, 98),  # Store as integer
        "report_available": True,
        "report_url": "https://example.com/whitepaper.pdf"  # NEW: Default whitepaper link
    }
    
    # Insert into MongoDB and get the inserted ID
    result = collection_attacks.insert_one(attack)
    attack['_id'] = result.inserted_id
    return attack

def get_all_logs(user_id):
    # Query MongoDB for attacks belonging to this user
    # Sort by timestamp descending (newest first)
    attacks = list(collection_attacks.find({"user_id": user_id}).sort("timestamp", -1))
    
    # Format for display
    formatted_attacks = []
    for attack in attacks:
        formatted_attacks.append({
            "id": str(attack["_id"]),  # Include ID for potential use
            "attack_type": attack["attack_type"],
            "time": attack["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "status": attack["status"],
            "performance": f"{attack['performance']}%",
            "report_available": attack.get("report_available", True),
            "report_url": attack.get("report_url", "https://example.com/whitepaper.pdf")  # NEW: Include report URL
        })
    
    return formatted_attacks

def get_attack_stats(user_id):
    total_attacks = collection_attacks.count_documents({"user_id": user_id})
    completed = collection_attacks.count_documents({"user_id": user_id, "status": "Completed"})
    in_progress = collection_attacks.count_documents({"user_id": user_id, "status": "In Progress"})
    failed = collection_attacks.count_documents({"user_id": user_id, "status": "Failed"})
    
    # Calculate average performance
    pipeline = [
        {"$match": {"user_id": user_id}},
        {"$group": {"_id": None, "avg_performance": {"$avg": "$performance"}}}
    ]
    avg_result = list(collection_attacks.aggregate(pipeline))
    avg_performance = round(avg_result[0]["avg_performance"], 1) if avg_result else 0
    
    return {
        "total": total_attacks,
        "completed": completed,
        "in_progress": in_progress,
        "failed": failed,
        "avg_performance": avg_performance
    }

# Deletes a specific attack 
def delete_attack(attack_id, user_id):
    result = collection_attacks.delete_one({
        "_id": ObjectId(attack_id),
        "user_id": user_id  # Ensure user owns this attack
    })
    return result.deleted_count > 0

# Lets you delete all attacks from the log 
def clear_all_attacks(user_id):
    result = collection_attacks.delete_many({"user_id": user_id})
    return result.deleted_count

# NEW: Update report URL for a specific attack
def update_report_url(attack_id, user_id, new_url):
    result = collection_attacks.update_one(
        {"_id": ObjectId(attack_id), "user_id": user_id},
        {"$set": {"report_url": new_url}}
    )
    return result.modified_count > 0

# TEST 
def seed_initial_attacks(user_id, count=5):
    for _ in range(count):
        generate_random_attack(user_id)

    print(f"Seeded {count} attacks for user {user_id}")
