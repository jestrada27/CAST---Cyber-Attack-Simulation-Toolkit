from datetime import datetime
from bson import ObjectId
import random
from database import database_name
from flask import jsonify


# Collections
collection_users = database_name["users"]
collection_attacks = database_name["attacks"]  # NEW: Store attacks here


groups_collection = database_name['groups']
report_collection = database_name['reports']


# Attack types and statuses
attack_types = ["SQL Injection", "DNS", "XSS", "Brute Force", "Replay"]
statuses = ["Stored to Local", "In Progress", "Completed", "Failed"]


def generate_random_attack(user_id):
   attack = {
       "user_id": ObjectId(user_id),  # Link attack to user
       "attack_type": random.choice(attack_types),
       "timestamp": datetime.utcnow(),  # Store as datetime object
       "status": random.choice(statuses),
      #  "performance": random.randint(0, 100),  # Store as integer
       "report_available": True,
       "report_url": "https://example.com/whitepaper.pdf"  # NEW: Default whitepaper link
   }
  
   # Insert into MongoDB and get the inserted ID
   result = collection_attacks.insert_one(attack)
   attack['_id'] = result.inserted_id
   return attack




#-----is this the same as get logs?-----
def get_all_logs(user_id):
   # Query MongoDB for attacks belonging to this user
   # Sort by timestamp descending (newest first)
   attacks = list(collection_attacks.find({"user_id": ObjectId(user_id)}).sort("timestamp", -1))
   #attacks = list(collection_attacks.find({"user_id": user_id}).sort("timestamp", -1))
  
  
   # Format for display
   formatted_attacks = []
   for attack in attacks:
       formatted_attacks.append({
           "id": str(attack["_id"]),  # Include ID for potential use
           "attack_type": attack["attack_type"],
           "time": attack["timestamp"].strftime("%Y-%m-%d_%H-%M-%S"),
           "status": attack["status"],
         #   "performance": f"{attack['performance']}%",
           "report_available": attack.get("report_available", True),
           "report_url": attack.get("report_url", "https://example.com/whitepaper.pdf")  # NEW: Include report URL
       })
  
   return formatted_attacks


def get_attack_stats(user_id):
   total_attacks = collection_attacks.count_documents({"user_id": ObjectId(user_id)})
   completed = collection_attacks.count_documents({"user_id": ObjectId(user_id), "status": "Completed"})
   in_progress = collection_attacks.count_documents({"user_id": ObjectId(user_id), "status": "In Progress"})
   failed = collection_attacks.count_documents({"user_id": ObjectId(user_id), "status": "Failed"})
  
   # Calculate average performance
   pipeline = [
       {"$match": {"user_id": ObjectId(user_id)}},
       {"$group": {"_id": None, "avg_performance": {"$avg": "$performance"}}}
   ]
   avg_result = list(collection_attacks.aggregate(pipeline))
   # avg_performance = round(avg_result[0]["avg_performance"], 1) if avg_result else 0
  
   return {
       "total": total_attacks,
       "completed": completed,
       "in_progress": in_progress,
       "failed": failed,
      #  "avg_performance": avg_performance
   }


# Deletes a specific attack
def delete_attack(attack_id, user_id):
   result = collection_attacks.delete_one({
       "_id": ObjectId(attack_id),
       "user_id": ObjectId(user_id)  # Ensure user owns this attack
   })
   return result.deleted_count > 0


# Lets you delete all attacks from the log
def clear_all_attacks(user_id):
   result = collection_attacks.delete_many({"user_id": ObjectId(user_id)})
   delete_periodic_log = report_collection.delete_many({"user_id": ObjectId(user_id)})
   return result.deleted_count


# NEW: Update report URL for a specific attack
def update_report_url(attack_id, user_id, new_url):
   result = collection_attacks.update_one(
       {"_id": ObjectId(attack_id), "user_id": ObjectId(user_id)},
       {"$set": {"report_url": new_url}}
   )
   return result.modified_count > 0


# TEST
def seed_initial_attacks(user_id, count=5):
   for _ in range(count):
       generate_random_attack(user_id)


   print(f"Seeded {count} attacks for user {user_id}")


#added - Noah
#formats the report to look right for the ui page 
def serialize(report):
   return {
      "_id": str(report["_id"]),
      "user_id": str(report["user_id"]),
      "generated_at": report.get("generated_at").strftime("%Y-%m-%d_%H-%M-%S") if report.get("generated_at") else "",
      "report_url": report.get("report_url", "")
   }

#function to make sure the attack log is formatted correctly when it's passed as a parameter
#attack log information is formatted for the when it shows in db and in ui
def serialize_attack_log(attack):
   return {
        "id": str(attack["_id"]),
        "user_id": str(attack["user_id"]),
        "attack_type": attack["attack_type"],
        "time": attack["timestamp"].strftime("%Y-%m-%d_%H-%M-%S"),
        "status": attack["status"],
      #   "performance": f"{attack['performance']}%",
        "report_available": attack.get("report_available", True),
        "report_url": attack.get("report_url", "")
    }


#function to get any reports for a specific user in the reports collection
def getReportsForUser(user_id):
   return list(report_collection.find({"user_id": ObjectId(user_id)}).sort("generated_at", -1))
   #return list(collection_attacks.find({"user_id": ObjectId(user_id)}).sort("timestamp", -1))
   

#function to get and filter attack logs that the user has.
def get_filtered_logs(
      user_id, attack_type, status, 
      sorter="Newest"):
   
   #gets the user id in order to be tied to that so all the attack logs the user has can be seen
   #attack type is checked to display specific attack type chosen
   user_obj = {"user_id": ObjectId(user_id)}
   if attack_type and attack_type != "All":
      user_obj["attack_type"] = attack_type

   #status is checked for specific status
   if status and status != 'All':
      user_obj["status"] = status

   #performance is checked for specific performance
   # if performance and performance != "All":
   #    if performance == "1-50":
   #       user_obj["performance"] = {"$gte": 1, "$lte": 50}
   #    elif performance == "51-100": 
   #       user_obj["performance"] = {"$gte": 51, "$lte": 100}

   #Soritng by different things. Lets the user sort the logs page based on this.
   #sorts and orders the list of logs by the time, performance, type, or status.
   if sorter == "Newest":
      sorting_by = "timestamp"
      base_sort = -1
   elif sorter == "Oldest":
      sorting_by = "timestamp"
      base_sort = 1
   # elif sorter == "Performance High":
   #    sorting_by = "performance"
   #    base_sort = -1
   # elif sorter == "Performance Low":
   #    sorting_by = "performance"
   #    base_sort = 1
   elif sorter == "Attacks A-Z":
      sorting_by = "attack_type"
      base_sort = 1
   elif sorter == "Attacks Z-A":
      sorting_by = "attack_type"
      base_sort = -1
   elif sorter == "Stored to Local - Failed":
      sorting_by = "status"
      base_sort = 1
   elif sorter == "Failed - Stored to Local":
      sorting_by = "status"
      base_sort = -1
   else:
      sorting_by = "timestamp"
      base_sort = -1
 
   #gets a list of the sorted/filtered attacks and then using the serialize function to format them correctly
   attacks_sort_filtered = list(collection_attacks.find(user_obj).sort(sorting_by, base_sort))
   #attacks_sort_filtered = list(collection_attacks.find(user).sort("timestamp", -1))

   return [serialize_attack_log(attack) for attack in attacks_sort_filtered]


# def periodicReport(user_id):

#    user_obj = {"user_id": ObjectId(user_id)}

from flask import send_file, session
from io import BytesIO
import json

def json_attack_report(attack_id, user_id):
   result = collection_attacks.find_one({
       "_id": ObjectId(attack_id),
       "user_id": ObjectId(user_id)})
   
   return result


def last_periodic_report(user_id):

   #user_obj = {"user_id": ObjectId(user_id)}
   return report_collection.find_one(
      {"user_id": ObjectId(user_id), 
      "report": "periodic"}, 
      sort=[("generated_at", -1)])


def periodic_json(attacks):

   #attacks_formatted = [serialize_attack_log(attack) for attack in attacks]
   # return jsonify({
   #    "generated_at": datetime.utcnow(),
   #    "attack_amount": len(attacks_formatted),
   #    "attacks": attacks_formatted
   # })
   periodic_json_data = {
      "generated_at": datetime.utcnow(),
      "attack_amount": len(attacks),
      "attacks": attacks
   }
   
   
   username = session.get("username")
   filename = f"Periodic_Report_{username}_{periodic_json_data['generated_at'].strftime('%Y-%m-%d_%H-%M-%S')}.json" 
   json_byte_data = BytesIO(json.dumps(periodic_json_data, indent=4, default=str).encode("utf-8"))
   json_byte_data.seek(0)

   return send_file(
      json_byte_data, 
      mimetype="application/json",
      as_attachment=True, 
      download_name=filename
      )
      
# def periodic_pdf():
#    pass

