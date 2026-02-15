from flask import Blueprint, request, session, jsonify
from .user_manage import  create_group, userJoinServer, inviteUserToServer, getUserServers, addUserToServer, banUserFromServer, changePrivilegeForUser, getUsersForServer, getAllActivityForUser, getActivityForUser

user_manage_bp = Blueprint("user_management", __name__, url_prefix="/groups")

#route for creating the user group.
@user_manage_bp.route("/create_user_group", methods=["POST"])
def create_user_group():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    #gets the data needed for the group
    data = request.get_json()
    name = data.get("name")
    #owner = data.get("owner")
    owner = session["user_id"]
    
    if not name:
        return {"success": False, "message": "Missing name"}, 400
    #uses the create group function to create the based on the group name and owner/creator
    group_id, user_key, admin_key = create_group(name, owner)
    if not group_id:
        return jsonify({"group_id": group_id, "user_key": user_key, "admin_key": admin_key})
    #returns the created group information for route
    return jsonify({"success": True, "group_id": str(group_id), "user_key": user_key, "admin_key": admin_key})


#route for getting the list of the users from the group/server
@user_manage_bp.route("/<group_id>/group_users", methods=["GET"])
def get_server_users(group_id):
    if "user_id" not in session:
        return jsonify({"success": False}), 401
    #uses the function for the route and returns the users
    group_users = getUsersForServer(group_id)
    return jsonify({"users": group_users})


#@user_manage_bp.route("/user_activity/<username>", methods=["GET"])
#route to get the user activity for the user in the server
@user_manage_bp.route("/user_activity/<user_id>/<group_id>", methods=["GET"])
def user_activity(user_id, group_id):
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    #uses the function to return a user's server/group activity
    user_activity = getActivityForUser(user_id, group_id)
    return jsonify({"activity": user_activity })

#route to get the user activity for the user
@user_manage_bp.route("/user_all_activity/<user_id>", methods=["GET"])
def get_all_activity(user_id):
     
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    #uses the function to return a user's actiity
    all_activity = getAllActivityForUser(user_id)
    return jsonify({"activity": all_activity })


#route that's used for changing the user's privilege 
@user_manage_bp.route("/change_privilege", methods=["POST"])
def change_privilege():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    
    #gets the user data for changing 
    data = request.get_json()
    if not data:
        return {"success": False, "message": "Invalid"}, 400
    #admin = data.get("admin")
    admin = session["user_id"]
    #user_target = data.get("username")
    user_target = data.get("user_id")
    role = data.get("role")
    group_id = data.get("group_id")
    admin_key = data.get("admin_key")

    #checks for changing privilege
    if not all([user_target, role, group_id, admin_key]):
        return jsonify({"success": False, "message": "Missing fields"}), 400
    
    if admin == user_target:
        return jsonify({"success": False, "message": "Can't change your own privilege"}), 400

    #uses the function to change the user's privilege and returns if the change worked or not
    privilege_change = changePrivilegeForUser(admin, user_target, role, group_id, admin_key)
    if not privilege_change:
        return jsonify({"success": False}), 403
    
    return jsonify({"success": True})

#route that is used to invite the user to the group
@user_manage_bp.route("/invite_user", methods=["POST"])
def invite_user():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    #gets the data for the user to be invited
    data = request.get_json()
    if not data:
        return jsonify({"success": False}), 400
    #admin = data.get("admin")
    admin = session["user_id"]
    group_id = data.get("group_id")
    admin_key = data.get("admin_key")
    invited_user = data.get("invited_user")

    if not all([group_id, admin_key, invited_user]):
        return jsonify({"success": False, "message": "Missing fields"}), 400
    #invites the specific user to the user and returns the invite if it worked.
    invite_success = inviteUserToServer(admin, group_id, admin_key, invited_user)
    if not invite_success: 
        return jsonify({"success": False}), 403
    #return jsonify({"success": True, "invite": invite})
    return jsonify({"success": True})

#route to ban a specific user from the server
@user_manage_bp.route("/ban_user", methods=["POST"] )
def ban_user():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    #gets the specific user data so the user can get banned
    data = request.get_json()
    if not data:
        return jsonify({"success": False}), 400
    #admin = data.get("admin")
    admin = session["user_id"]
    user_target = data.get("user_id")
    group_id = data.get("group_id")
    admin_key = data.get("admin_key")
    #checks before banning
    if not all([user_target, group_id, admin_key]):
        return jsonify({"success": False, "message": "Missing fields"}), 400
    
    if admin == user_target:
        return jsonify({"success": False, "message": "Can't ban yourself"}), 400
    #uses the function to ban the user from the server/group
    ban_request, _ = banUserFromServer(admin, user_target, group_id, admin_key)
    if not ban_request:
        return jsonify({"success": False}), 403
    return jsonify({"success": True})


# @user_manage_bp.route("/add_user", methods=["POST"] )
# def add_user():
#     if "user" not in session:
#         return {"success": False, "message": "Not logged in"}, 401
    
#     data = request.get_json()
#     username = data.get("username")
#     group_id = data.get("group_id")

#     added_user, key = addUserToServer(username, group_id)
#     if not added_user:
#           return jsonify({"success": False}), 400
    
#     return jsonify({"success": True, "user_key": key})

#route for the user to be able to join the group
@user_manage_bp.route("/join_group", methods=["POST"])
def join_group():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    #gets the data for the user and invite
    data = request.get_json()
    if not data:
        return jsonify({"success": False}), 400
    #username = data.get("username")
    user_id = session["user_id"]
    group_id = data.get("group_id")
    if not group_id:
          return jsonify({"success": False}), 400
    # invite = data.get("invite")

    # if not invite:
    #     return {"success": False, "message": "No invite"}, 400
    #uses the function to have the user join the server based on the invite that they got. returns if they joined
    join_check, key = userJoinServer(user_id, group_id)
    if not join_check:
        return jsonify({"success": False}), 403
    return jsonify({"success": True, "user_key": key})

#route that returns the groups that a specfic user is in
@user_manage_bp.route("/user_group", methods=["GET"])
def user_group():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    #uses the function to get the list of groups for the user
    user_in_groups = getUserServers(session["user_id"])
    return jsonify({"groups": user_in_groups})
