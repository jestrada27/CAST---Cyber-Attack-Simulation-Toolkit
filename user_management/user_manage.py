#from flask import Flask, request, session, redirect, render_template, flash, url_for

from database import database_name
from bson import ObjectId
import secrets

collection_users = database_name['users']
groups_collection = database_name['groups']

def object_id(id):

    if isinstance(id, ObjectId):
        return id
    return ObjectId(id)


def create_group(name, owner):

  
    group_id = groups_collection.insert_one({
    "name": name,
    "owner": object_id(owner), 
    "banned": [],
    "invites": []
    }).inserted_id

    user_key = secrets.token_urlsafe(16)
    admin_key = secrets.token_urlsafe(16)

    # collection_users.update_one(
    #     {"username": owner}, 
    #     {"$addToSet": {"groups": {"group_id": str(group_id), "role": "admin"},
    #     "group_keys": {"group_id": str(group_id), "user_key": user_key, "admin_key": admin_key}
    #     }
    #     })
    # return str(group_id), user_key, admin_key

    #user_check = collection_users.find_one({"username": owner})
    user_check = find_user(owner)
    if not user_check:
        return None, None, None
    
    collection_users.update_one(
    {"_id": object_id(owner)},
    {
        "$push": {
            "groups": {"group_id": group_id,"role": "admin"},
            "group_keys": {"group_id": group_id, "user_key": user_key, "admin_key": admin_key}}
        }
    )

    return group_id, user_key, admin_key


def admin_check(user_id, group_id, key):

    user = find_user(user_id)
    if not user: return False

    # for group in user.get("groups", []):
    #     if group["group_id"] == group_id and group["role"] == "admin":
    #         if key: 
    #             for indv_key in user.get("group_keys", []):
    #                 if indv_key["group_id"] == group_id and indv_key("admin_key") == key:
    #                     return True
    #             return False
    #         return True
    # return False

    # return collection_users.find_one({"username": username, "groups": {"$elemMatch": {"group_id": group_id, "role": "admin"}}
    #                                   }) is not None
    group_id = object_id(group_id)
    is_admin = any(group["group_id"] == group_id and group["role"] == "admin" for group in user.get("groups", []))
    if not is_admin: return False

    if key:
        for indv_key in user.get("group_keys", []):
            if (indv_key["group_id"] == group_id and indv_key.get("admin_key") == key):
                return True
        return False
    return True
 

# def find_username(username):
#     return collection_users.find_one({"username": username})

def find_user(user_id):
    return collection_users.find_one({"_id": object_id(user_id)})


def find_group(group_id):
    #return groups_collection.find_one({"_id": ObjectId(group_id)})
    group_id = object_id(group_id)
    return groups_collection.find_one({"_id": group_id})


#def banned_user(username, group_id):
def banned_user(user_id, group_id):
    #group_id = object_id(group_id)
    group_ban = find_group(group_id)
    if not group_ban:
        return False

    #return group_ban and username in group_ban.get("banned", [])
    #return group_ban and user_id in group_ban.get("banned", [])
    return object_id(user_id) in group_ban.get("banned", [])



#server = group
#def getUsersForServer(user, group_id): #users: Gets a list of all users with their roles.
def getUsersForServer(group_id):
    # group_members = collection_users.find({"groups.group_id": group_id})
    # member_list = []
    # for member in group_members:
    #     for group in member.get("groups", []):
    #         if group["group_id"] == group_id:
    #             member_list.append({"username": member["username"], "role": group["role"]})
    # return member_list

    # user_find = collection_users.find({"groups.group_id": group_id},{"username": 1, "groups": 1} )
    group_id = object_id(group_id)
    user_find = collection_users.find({"groups.group_id": group_id},{"username": 1, "groups": {"$elemMatch": {"group_id": group_id}}} )
    users_list = []

    for user in user_find:
        for group in user.get("groups", []):
            if group["group_id"] == group_id:
                users_list.append({"username": user["username"], "role": group["role"]})
    # return users_list
    # for user in user_find:
    #     group = user.get("groups", [])[0]
    #     users_list.append({"username": user["username"], "role": group["role"]})

    return users_list


def getActivityForUser(user_id, group_id): #activities: Gets activity for user (in a specific server)
    user_activity = find_user(user_id)
    group_id = object_id(group_id)
    if not user_activity:
        return []
    return [activity for activity in user_activity.get("activity", []) if activity.get("group_id") == group_id]


def getAllActivityForUser(user_id): #activities: Gets all activity a user has.
    user_activity = find_user(user_id)
    if user_activity:
        return user_activity.get("activity", [])
    else: return []


#def changePrivilegeForUser(admin, user, newPrivelige): #response status: Change the privilege for user. Could be changing them to admin, removing their admin, etc.
def changePrivilegeForUser(admin, user_id, newPrivelige, group_id, admin_key):
    if not admin_check(admin, group_id, key=admin_key):
        return False
    group_id = object_id(group_id)
    #privilege_change = collection_users.update_one({"username": user, "groups.group_id": group_id},
                                                  # {"$set": {"groups.$.role": newPrivelige}}).modified_count
    privilege_change = collection_users.update_one({"_id": object_id(user_id), "groups.group_id": group_id},
                                                   {"$set": {"groups.$.role": newPrivelige}}).modified_count
    return privilege_change == 1


#def inviteUserToServer(admin, user, group_id): #response status: Invites a user to a server. As of right now, i only plan on letting admins invite people to servers.
def inviteUserToServer(admin, group_id, admin_key):

    if not admin_check(admin, group_id, admin_key):
        return False, None
    
    invite = secrets.token_urlsafe(16)
    #group_id = object_id(group_id)
    groups_collection.update_one({"_id": object_id(group_id)}, {"$addToSet": {"invites": invite}})
    return True, invite


def banUserFromServer(admin, user_id, group_id, admin_key): #response status: Bans a user from a server. Needs an admin privilege to be able to do this. 
    if not admin_check(admin, group_id, admin_key):
        return False, None
    #group_id = object_id(group_id)
    groups_collection.update_one({"_id": object_id(group_id)}, {"$addToSet": {"banned": object_id(user_id)}})

    #collection_users.update_one({"username": user_id}, {"$pull": {"groups": {"group_id": group_id}, "group_keys": {"group_id": group_id}}})
    collection_users.update_one({"_id": object_id(user_id)}, {"$pull": {"groups": {"group_id": group_id}, "group_keys": {"group_id": group_id}}})
    return True, None


def addUserToServer(user_id, group_id):

    user_id = object_id(user_id)
    group_id = object_id(group_id)

    if banned_user(user_id, group_id):
        return False, None
    
    #user_check = collection_users.find_one({"username": user_id})
    user_check = find_user(user_id)
    if not user_check: return False, None

    #in_group = collection_users.find_one({"username": user_id, "groups.group_id": group_id})
    in_group = collection_users.find_one({"_id": user_id, "groups.group_id": group_id})
    if in_group: return False, None

    user_key = secrets.token_urlsafe(16)
    #group_addition = 
    # collection_users.update_one({
    #     "username": username},
    #     {"$push": {"groups": {"group_id": group_id, "role": "member"}, 
    #                    "group_keys": {"group_id": group_id, "user_key": user_key}
    #     }}

    # )
    collection_users.update_one({
        "_id": user_id},
        {"$push": {"groups": {"group_id": group_id, "role": "member"}, 
                       "group_keys": {"group_id": group_id, "user_key": user_key}
        }}

    )
    #return group_addition.modified_count == 1, user_key
    return True, user_key


def userJoinServer(user_id, invite):
    group_invite = groups_collection.find_one({"invites": invite})
    if not group_invite:
        return False, None
    
    if object_id(user_id) in group_invite.get("banned", []):
        return False, None
    #group_id = object_id(group_id)
    groups_collection.update_one({"_id": group_invite["_id"]}, {"$pull": {"invites": invite}})

    added_conf, user_key = addUserToServer(user_id, group_invite["_id"])

    if not added_conf:
        return False, None
    return True, user_key


def getUserServers(user_id):
    user_check = find_user(user_id)

    if not user_check:
        return []
    groups_list = []
    for each_group in user_check.get("groups", []):
        group = find_group(each_group["group_id"])

        if group:
            groups_list.append({"group_id": str(group["_id"]), "name": group["name"], "role": each_group["role"]})

    return groups_list