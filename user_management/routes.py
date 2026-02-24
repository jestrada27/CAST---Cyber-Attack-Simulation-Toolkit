from flask import Blueprint, request, session, jsonify
from .user_manage import  create_group, userJoinServer, inviteUserToServer, getUserServers, addUserToServer, banUserFromServer, changePrivilegeForUser, getUsersForServer, getAllActivityForUser, getActivityForUser, getUsersInvitations

user_manage_bp = Blueprint("user_management", __name__, url_prefix="/groups")


@user_manage_bp.route("/create_user_group", methods=["POST"])
def create_user_group():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    data = request.get_json()
    name = data.get("name")
    #owner = data.get("owner")
    owner = session["user_id"]
    
    if not name:
        return {"success": False, "message": "Missing name"}, 400

    group_id, user_key, admin_key = create_group(name, owner)
    if not group_id:
        return {"success": False, "message": "Group id empty, create_user_group failed"}
        #return jsonify({"group_id": group_id, "user_key": user_key, "admin_key": admin_key})
    
    return jsonify({"success": True, "group_id": str(group_id), "user_key": user_key, "admin_key": admin_key})
    

@user_manage_bp.route("/<group_id>/group_users", methods=["GET"])
def get_server_users(group_id):
    if "user_id" not in session:
        return jsonify({"success": False}), 401
    
    group_users = getUsersForServer(group_id)
    return jsonify({"users": group_users})


#@user_manage_bp.route("/user_activity/<username>", methods=["GET"])
@user_manage_bp.route("/user_activity/<user_id>/<group_id>", methods=["GET"])
def user_activity(user_id, group_id):
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    
    user_activity = getActivityForUser(user_id, group_id)
    return jsonify({"activity": user_activity })


@user_manage_bp.route("/user_all_activity/<user_id>", methods=["GET"])
def get_all_activity(user_id):
     
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
     
    all_activity = getAllActivityForUser(user_id)
    return jsonify({"activity": all_activity })


@user_manage_bp.route("/change_privilege", methods=["POST"])
def change_privilege():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    
    
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

    if not all([user_target, role, group_id, admin_key]):
        return jsonify({"success": False, "message": "Missing fields"}), 400
    
    if admin == user_target:
        return jsonify({"success": False, "message": "Can't change your own privilege"}), 400

    privilege_change = changePrivilegeForUser(admin, user_target, role, group_id, admin_key)
    if not privilege_change:
        return jsonify({"success": False}), 403
    
    return jsonify({"success": True})


@user_manage_bp.route("/invite_user", methods=["POST"])
def invite_user():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    data = request.get_json()
    if not data:
        return jsonify({"success": False}), 400
    #admin = data.get("admin")
    admin = session["user_id"]
    group_id = data.get("group_id")
    #admin_key = data.get("admin_key")
    invited_user = data.get("invited_user_name")

    if not all([group_id, invited_user]):
        return jsonify({"success": False, "message": "Missing fields"}), 400
    
    invite_succuess = inviteUserToServer(admin, group_id, invited_user)
    if not invite_succuess:
        return jsonify({"success": False}), 403
    return jsonify({"success": True})


@user_manage_bp.route("/get_user_invites", methods=["GET"])
def get_user_invites():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    
    groups_were_invited_to = getUsersInvitations(session["user_id"])

    return jsonify({"success": True, "groups": groups_were_invited_to})

@user_manage_bp.route("/ban_user", methods=["POST"] )
def ban_user():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    
    data = request.get_json()
    if not data:
        return jsonify({"success": False}), 400
    #admin = data.get("admin")
    admin = session["user_id"]
    user_target = data.get("user_id")
    group_id = data.get("group_id")
    admin_key = data.get("admin_key")

    if not all([user_target, group_id, admin_key]):
        return jsonify({"success": False, "message": "Missing fields"}), 400
    
    if admin == user_target:
        return jsonify({"success": False, "message": "Can't ban yourself"}), 400

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


@user_manage_bp.route("/join_group", methods=["POST"])
def join_group():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    
    data = request.get_json()
    if not data:
        return jsonify({"success": False}), 400
    #username = data.get("username")
    user_id = session["user_id"]
    invite = data.get("group_id")

    if not invite:
        return {"success": False, "message": "No invite"}, 400

    join_check, key = userJoinServer(user_id, invite)
    if not join_check:
        return jsonify({"success": False}), 403
    return jsonify({"success": True, "user_key": key})

@user_manage_bp.route("/deny_invite", methods=["POST"])
def deny_invite():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    
    data = request.get_json()
    if not data:
        return jsonify({"success": False}), 400
    user_id = session["user_id"]
    group_id = data.get("group_id")

    if not group_id:
        return {"success": False, "message": "Missing field group_id"}, 400

    denyInvite(user_id, group_id)
    
    return jsonify({"success": True})


@user_manage_bp.route("/user_group", methods=["GET"])
def user_group():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    
    user_in_groups = getUserServers(session["user_id"])
    return jsonify({"groups": user_in_groups})
