from bson import ObjectId
from datetime import datetime
from database import database_name
from flask import jsonify

#import statements above and variable for target database collection
collection_targets = database_name["targets"]

#function to allow a target to be whitelisted
def whitelist_target(target_id, owner_name):
    target_id = ObjectId(target_id)
    if not target_id:
        return False, "Not a target"
 
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
    target_id = ObjectId(target_id)
    #finds the target
    found_target = collection_targets.find_one(
        {"_id": target_id, 
         "owner": owner_name
        })
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
def remove_target_whitelist():
    pass





