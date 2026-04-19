from bson import ObjectId
from datetime import datetime
from database import database_name
from flask import jsonify

#import statements above and variable for target database collection
collection_targets = database_name["targets"]
collection_experiments = database_name["experiments"]

#function to allow a target to be whitelisted
def whitelist_target(target_id, owner_name):
    # target_id = ObjectId(target_id)
    # if not target_id:
    #     return False, "Not a target"

    if not ObjectId.is_valid(target_id):
        return False, "Not a target"
    target_id = ObjectId(target_id)

    target_exists = collection_targets.find_one({
        "_id": target_id,
        "owner": owner_name},
        {"consent_status": 1}
    )

    if not target_exists: 
        return False, "Target not found"
    if target_exists.get("consent_status") == "approved":
        return False, "Target whitelisted already"
    
 
    #gets the target and then whitelists it so it's approved for being attacked
    result = collection_targets.update_one(
        {"_id": target_id, 
        "owner": owner_name},
        {"$set": {"consent_status": "approved"}},
    )

    #returns target result if whitelisted
    if result.matched_count == 0:
        return False, "Target not found"
    
    return True, "Target whitelisted"


#function to check if a target is whitelisted
def is_whitelisted(target_id, owner_name): 
    if not ObjectId.is_valid(target_id):
        return False
    target_id = ObjectId(target_id)
    #finds the target
    found_target = collection_targets.find_one(
        {"_id": target_id, 
         "owner": owner_name
        }, 
        {"consent_status": 1})
    if not found_target:
        return False
    #checks if whitelisted and returns T or F
    return found_target.get("consent_status") == "approved"


#gets the list of all the targets that the owner has whitelisted and returns them
def get_whitelisted_targets(owner_name):
    whitelisted_list = list(collection_targets.find(
        {"owner": owner_name,
        "consent_status": "approved"
        }))
    return whitelisted_list


#function to remove whitelist
def remove_target_whitelist(target_id, owner_name):

    if not ObjectId.is_valid(target_id):
        return False, "Not a target"
    target_id = ObjectId(target_id)

    remove_result = collection_targets.update_one(
        {"_id": target_id, "owner": owner_name},
        {"$set": {"consent_status": "revoked"}
    })

    if remove_result.matched_count == 0:
        return False, "Target not found"

    return True, "Removed whitelist"



from urllib.parse import urlparse
import re

def is_valid_target(ip_or_url):
    try:
        parsed = urlparse(ip_or_url)

        # netloc = parsed.netloc or parsed.path

        # if not netloc:
        #     return False

        # return True
        if parsed.scheme in ["http", "https"] and parsed.netloc:
            return True
        
        if re.match("^localhost(:\d+)?$", ip_or_url):
            return True
        
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$", ip_or_url):
            return True
        
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:\d+)?$", ip_or_url):
            return True
        return False
   
    except:
        return False
    

def target_validation(target_name, ip_or_url, owner_name):
    if not target_name or not ip_or_url:
        return False, "Not a valid target / not valid target data"
    
    if collection_targets.find_one({"owner": owner_name, "name": target_name}):
        return False, "Target exists"

    # url_pattern = r"^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    # localhost = r"^(https?:\/\/)?localhost(:\d+)?$"
    # ip = r"^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d+)?$"

    # if not (re.match(url_pattern, ip_or_url) or re.match(localhost, ip_or_url) or re.match(ip, ip_or_url)):
    #     return False, "Invalid URL/IP"
    if not is_valid_target(ip_or_url):
        return False, "Invalid URL/IP"
    
    return True, "Valid"
    

def target_by_status_list(owner_name):
    targets_list = list(collection_targets.find({"owner": owner_name}))
    
    result_options = {
        "pending": [],
        "approved": [], 
        "revoked": []
    }

    for target in targets_list:
        target["_id"] = str(target["_id"])
        status = target.get("consent_status", "pending")

        if status == "approved":
            result_options["approved"].append(target)
        elif status == "revoked":
            result_options["revoked"].append(target)
        else:
            result_options["pending"].append(target)

    return result_options


def whitelist_toggle(target_id, owner_name):
    if not ObjectId.is_valid(target_id):
        return False, "Not a target"
    target_id = ObjectId(target_id)

    target = collection_targets.find_one({
        "_id": target_id, "owner": owner_name},
        {"consent_status": 1}
    )
    if not target: 
        return False, "Target not found"
    
    target_new_status = "approved" if target.get("consent_status") != "approved" else "revoked"

    result = collection_targets.update_one(
        {"_id": target_id, 
        "owner": owner_name},
        {"$set": {"consent_status": target_new_status}},
    )

    if result.matched_count == 0:
        return False, "Target not found"
    
    return True, f"Target set to {target_new_status}"


def delete_experiment_target(target_id, owner_name):
    if not ObjectId.is_valid(target_id):
        return False, "Not a target"
    target_id = ObjectId(target_id)

    target_result = collection_experiments.delete_one({
        "_id": target_id, "owner": owner_name},
    )

    if target_result.deleted_count == 0:
        return False, "Target not found"
    
    return True, "Target deleted"