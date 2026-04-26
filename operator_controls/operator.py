from bson import ObjectId
from datetime import datetime
from database import database_name
from flask import jsonify
from user_management.user_manage import admin_check, find_group

#database collections used and imports above
collection_attacks = database_name["attacks"]
collection_users = database_name['users']
groups_collection = database_name['groups']
collection_requests = database_name["attack_requests"] #experiments??
collection_experiments = database_name["experiments"]
collection_targets = database_name["targets"]

def authorized_operator_check(user_id, group_id):
    user = collection_users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return False

    group_id = ObjectId(group_id)

    for g in user.get("groups", []):
        if g["group_id"] == group_id and g["role"] == "admin":
            return True

    return False


#verifies that a group member is a part of the group
#goes through the group and checks to return T or F
def group_member_check(user_id, group_id):
    user = collection_users.find_one({"_id": ObjectId(user_id)})
    if not user: 
        return False
    for group in user.get("groups", []):
        if group["group_id"] == ObjectId(group_id):
            return True
    return False

# function to get the admin groups for the user (groups that the user is an admin of)
def get_admin_groups(user_id):
    found_user = collection_users.find_one({"_id": ObjectId(user_id)})
    if not found_user:
        return []
    
    operator_admin_groups = []
    for group in found_user.get("groups", []):
        if group.get("role") == "admin":
            group_information = groups_collection.find_one({"_id": group["group_id"]})
            if group_information:
                operator_admin_groups.append({
                    "group_id": str(group_information["_id"]),
                    "name": group_information.get("name", "Unknown")
                })

    return operator_admin_groups


#Function to let the operator approve an attack that a member requests
def approve_attack(user_id, attack_id, group_id):
    attack = collection_requests.find_one({"_id": ObjectId(attack_id)})
    #attack = placeholder_collection.find_one({"_id": ObjectId(attack_id), ObjectId(group_id)})
    if not attack: 
        return False, "No attack request for approval"
    
    #if not admin_check(user_id, attack["group_id"], admin_key):
    if not authorized_operator_check(user_id, attack["group_id"]): #fix
        return False, "Unauthorized user for operator controls"
    
    if attack["group_id"] != ObjectId(group_id):
        return False, "Not the right group"

    if attack["status"] != "pending":
       return False, "Attack no longer pending"
    #goes through the attack requests and then updates the request to approved and returns it
    collection_requests.update_one(
        {
            "_id": ObjectId(attack_id)},
            {"$set": {
                "status": "approved",
                "approved_by": ObjectId(user_id),
                "approved_at": datetime.utcnow()
            }}
    )
    
    return True, "Attack approved"

#Function to let the operator deny an attack that a member requests
def deny_attack(user_id, attack_id, group_id):
    attack = collection_requests.find_one({"_id": ObjectId(attack_id)})
        #attack = placeholder_collection.find_one({"_id": ObjectId(attack_id), ObjectId(group_id)})
    if not attack: 
        return False, "No attack request for approval"
    
    #if not admin_check(user_id, attack["group_id"], admin_key):
    if not authorized_operator_check(user_id, attack["group_id"]): #fix
        return False, "Unauthorized user for operator controls"
    
    if attack["group_id"] != ObjectId(group_id):
        return False, "Not the right group"


    if attack["status"] != "pending":
       return False, "Attack no longer pending"
        #goes through the attack requests and then updates the request to deny it and returns it
    collection_requests.update_one(
        {
            "_id": ObjectId(attack_id)},
            {"$set": {
                "status": "denied",
                "denied_by": ObjectId(user_id),
                "denied_at": datetime.utcnow()
            }}
    )

    return True, "Attack denied"

#lets the user cancel an attack request
def user_cancel_attack(user_id, attack_id):
    attack = collection_requests.find_one({"_id": ObjectId(attack_id)})
    if not attack:
        return False, "Cannot find attack/experiment"
    #checks for the request that the user made 
    if attack["submitted_by"] != ObjectId(user_id):
        return False, "Request belongs to another user"
    
    if attack["status"] != "pending":
        return False, "Attack has gone through already"
    #updates attack request to cancel it
    collection_requests.update_one({"_id": ObjectId(attack_id)},
    {"$set": {"status": "cancelled", "cancelled_at": datetime.utcnow()}})

    return True, "Attack cancelled"


#gets a list of the pending attack requests for a group so the operator can approve or deny
def get_pending_attack_requests(group_id, user_id):
    
    if not authorized_operator_check(user_id, group_id): #fix
        return False, "Unauthorized user for operator controls"
    
    #gets all of the requests based on group membership and formats them to be shown
    user_requests = list(collection_requests.find({"group_id": ObjectId(group_id),
    "status": "pending" 
    }))

    for request in user_requests:
        request["_id"] = str(request["_id"])
        request["group_id"] = str(request["group_id"])
        request["submitted_by"] = str(request["submitted_by"])
        user = collection_users.find_one({"_id": ObjectId(request["submitted_by"])})
        request["username"] = user["username"] if user else "Unknown"
        experiment = collection_experiments.find_one({
        "_id": request["experiment_id"]
    })
        # checks if its and experiment. if it is, it sets up everything for the request
        if experiment:
            request["module"] = experiment.get("module_id")
            request["attempts"] = experiment.get("attempts")
            request["rate_limit"] = experiment.get("rate_limit")
            request["target_id"] = str(experiment.get("target_id"))
        #checks for target and sets up request correctly
            target_id = experiment.get("target_id")
            request["target_id"] = str(target_id)
            found_target = collection_targets.find_one({"_id": target_id})

            if found_target:
                request["target_name"] = found_target.get("name", "Unknown target")
            else:
                request["target_name"] = "DELETED TARGET"
            
        else:
            request["module"] = experiment.get("module_id")
            request["target_id"] = "NONE"
            request["target_name"] = "DELETED TARGET"

    return True, user_requests

#gets all requests for everyone in the group
def get_all_requests(group_id, user_id, status=None):
    if not authorized_operator_check(user_id, group_id): 
        return False, "Unauthorized user for operator controls"
    user_id = ObjectId(user_id)
    group_id = ObjectId(group_id)

    found_group = {"group_id": group_id}
    if status:
        found_group["status"] = status


    #finds all requests and shows them based on the group
    user_requests = list(collection_requests.find(found_group))
    for request in user_requests:
        request["_id"] = str(request["_id"])
        request["group_id"] = str(request["group_id"])
        request["submitted_by"] = str(request["submitted_by"])
        user = collection_users.find_one({"_id": ObjectId(request["submitted_by"])})
        request["username"] = user["username"] if user else "Unknown"
        experiment = collection_experiments.find_one({
        "_id": request["experiment_id"]
    })
        # checks if its and experiment. if it is, it sets up everything for the request
        if experiment:
            request["module"] = experiment.get("module_id")
            request["attempts"] = experiment.get("attempts")
            request["rate_limit"] = experiment.get("rate_limit")
            request["target_id"] = str(experiment.get("target_id"))
        #checks for target and sets up request correctly
            target_id = experiment.get("target_id")
            request["target_id"] = str(target_id)
            found_target = collection_targets.find_one({"_id": target_id})

            if found_target:
                request["target_name"] = found_target.get("name", "Unknown target")
            else:
                request["target_name"] = "DELETED TARGET"
            
        else:
            request["module"] = "DELETED EXPERIMENT"
            request["target_id"] = "NONE"
            request["target_name"] = "DELETED TARGET"

    return True, user_requests

    
#gets the information relevant from the request to be shown to the operator
def get_request_info(user_id, attack_id):
    
    user_id = ObjectId(user_id)
    # group_id = ObjectId(group_id)
    attack_id = ObjectId(attack_id)
    attack = collection_requests.find_one({"_id": attack_id})

    if not attack:
        return False, "Cannot find attack/experiment"

    if not authorized_operator_check(user_id, attack["group_id"]): #fix
        return False, "Unauthorized user for operator controls"
    
    #after getting the information for the request it properly shows the relevant information
    attack["_id"] = str(attack["_id"])
    attack["group_id"] = str(attack["group_id"])
    attack["submitted_by"] = str(attack["submitted_by"])

    # gets experiment and checks for it. then sets up the experiement for the operator page
    experiment = collection_experiments.find_one({
    "_id": attack["experiment_id"]})
    
    if experiment:
        attack["module"] = experiment.get("module_id")
        attack["attempts"] = experiment.get("attempts")
        attack["rate_limit"] = experiment.get("rate_limit")
        attack["target_id"] = str(experiment.get("target_id"))
        attack["username"] = attack.get("username")

    return True, attack

#gets all of the requests for a specific user to be listed 
def get_user_requests(group_id, user_id, target_user_id, status=None):
    if not authorized_operator_check(user_id, group_id): 
        return False, "Unauthorized user for operator controls"
    
    target_user_id = ObjectId(target_user_id)
    group_id = ObjectId(group_id)

    #finds who submitted the request in a group
    found_requests = {
        "group_id": group_id,
        "submitted_by": target_user_id
    }

    if status:
        found_requests["status"] = status

    #gets the list of requests made by the user adn then shows it
    user_requests = list(collection_requests.find(found_requests))

    for request in user_requests:
        request["_id"] = str(request["_id"])
        request["group_id"] = str(request["group_id"])
        request["submitted_by"] = str(request["submitted_by"])

        # gets experiment and checks for it. then sets up the experiement for the operator page
        experiment = collection_experiments.find_one({
    "_id": request["experiment_id"]})

        if experiment:
            request["module"] = experiment.get("module_id")
            request["attempts"] = experiment.get("attempts")
            request["rate_limit"] = experiment.get("rate_limit")
            request["target_id"] = str(experiment.get("target_id"))
            request["username"] = request.get("username")

    return True, user_requests

#function that gets the members of the group for the operator
def group_members(group_id, user_id):
    if not authorized_operator_check(user_id, group_id): 
        return False, "Unauthorized user for operator controls"
    
    group_list = list(collection_users.find({
        "groups.group_id": ObjectId(group_id)
    }, {"username": 1}))

    serialization = []
    for user in group_list:
        serialization.append({
            "user_id": str(user["_id"]),
            "username": user.get("username", "Unknown")
        })
    return True, serialization