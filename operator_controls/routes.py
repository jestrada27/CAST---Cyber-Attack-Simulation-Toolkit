
from flask import Blueprint, request, session, jsonify, redirect, render_template, flash, url_for
from datetime import datetime
from bson import ObjectId
from database import database_name
from .operator import (approve_attack, deny_attack, get_pending_attack_requests,
user_cancel_attack, get_all_requests, get_request_info, get_user_requests, get_admin_groups, group_members)


#blueprint for route and database collection data
operator_bp = Blueprint("operator_cntrl_bp", __name__)

#route for the approve request to approve attacks
@operator_bp.route("/approve/<attack_id>", methods=["POST"])
def approve_attack_route(attack_id): #fix
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    #gets necessary varaibles 
    user_id = session["user_id"]
    data = request.get_json() or {}
    #admin_key = data.get("admin_key")
    group_id = data.get("group_id")
    # if not admin_key:
    #     return jsonify({"success": False, "message":"Not admin/no admin key"})

    #uses function to approve attack and returns it
    # attack_approved, approve_message = approve_attack(user_id, attack_id, admin_key, group_id) #fix
    attack_approved, approve_message = approve_attack(user_id, attack_id, group_id) #fix
    return jsonify({"success": attack_approved, "message": approve_message})


#route for the deny request to deny attacks
@operator_bp.route("/deny/<attack_id>", methods=["POST"])
def deny_attack_route(attack_id): #fix
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    #gets necessary varaibles 
    user_id = session["user_id"]
    data = request.get_json() or {}
    # admin_key = data.get("admin_key")
    group_id = data.get("group_id")
    # if not admin_key:
    #     return jsonify({"success": False, "message":"Not admin/no admin key"})
    
    #uses function to deny attack and returns it
    # attack_denied, deny_message = deny_attack(user_id, attack_id, admin_key, group_id) #fix
    attack_denied, deny_message = deny_attack(user_id, attack_id, group_id) #fix
    return jsonify({"success": attack_denied, "message": deny_message})


#route for getting all of the pending requests for the group
@operator_bp.route("/pending_requests/<group_id>", methods=["POST"])
def pending_requests_route(group_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    #gets necessary variables
    user_id = session["user_id"]
    data = request.get_json() or {}
    # admin_key = data.get("admin_key")
    # if not admin_key:
    #     return jsonify({"success": False, "message":"Not admin/no admin key"})
    
    #gets all of the requests using the function and returns it
    # got_requests, result = get_pending_attack_requests(group_id, user_id, admin_key)
    got_requests, result = get_pending_attack_requests(group_id, user_id)

    return jsonify({"success": got_requests, 
                    "request_data": result if got_requests else None,
                    "message": None if got_requests else "Requests not received"
    })


#route for canceling requests
@operator_bp.route("/cancel_attack/<attack_id>", methods=["POST"])
def cancel_request_route(attack_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    #uses the user_id with the attack id for the cancel function in order to cancel and then returns it
    user_id = session["user_id"]
    cancelled_request, cancel_message = user_cancel_attack(user_id, attack_id)
    return jsonify({"success": cancelled_request, "message": cancel_message})


#route for getting all of the requests for a group
@operator_bp.route("/all_requests/all/<group_id>", methods=["POST"])
def get_requests_route(group_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    #gets all the necessary variables needed for the request
    user_id = session["user_id"]
    data = request.get_json() or {}
    # admin_key = data.get("admin_key")
    status = data.get("status")
    # if not admin_key:
    #     return jsonify({"success": False, "message":"Not admin/no admin key"})
    
    #gets the requests using the function and returns it
    # got_requests, result = get_all_requests(group_id, user_id, admin_key, status)
    got_requests, result = get_all_requests(group_id, user_id, status)

    return jsonify({"success": got_requests, 
                    "request_data": result if got_requests else None,
                    "message": None if got_requests else "Requests not received"
    })


#route for getting the details of the user requests
@operator_bp.route("/info_request/<attack_id>", methods=["POST"])
def request_details_route(attack_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    #gets the necessary variables
    user_id = session["user_id"]
    data = request.get_json() or {}
    # admin_key = data.get("admin_key")

    # if not admin_key:
    #     return jsonify({"success": False, "message":"Not admin/no admin key"})
    
    
    #uses the function to get the detail info for the specific request and returns it
    # details_requested, result = get_request_info(user_id, attack_id, admin_key)
    details_requested, result = get_request_info(user_id, attack_id)

    return jsonify({"success": details_requested, "data": result})


#route for getting the list of the user's requests
@operator_bp.route("/user_requests/<group_id>/<target_user_id>", methods=["POST"])
def user_requests_route(group_id, target_user_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    #gets necessary variables
    user_id = session["user_id"]
    data = request.get_json() or {}
    # admin_key = data.get("admin_key")
    status = data.get("status")

    # if not admin_key:
    #     return jsonify({"success": False, "message":"Not admin/no admin key"})
    
    #gets the user requests using the function and returns them
    # user_info_requested, result = get_user_requests(group_id, user_id, target_user_id, admin_key, status)
    user_info_requested, result = get_user_requests(group_id, user_id, target_user_id, status)

    return jsonify({"success": user_info_requested, 
                    "request_data": result if user_info_requested else None,
                    "message": None if user_info_requested else "Requests not received"
    })


from database import database_name
collection_users = database_name["users"]
@operator_bp.route("/operator_dashboard")
def operator_page():
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
   
   user_id = ObjectId(session["user_id"])
   found_user = collection_users.find_one({"_id": user_id})

   if not found_user:
    #    return redirect("/login")
    return redirect("/")
   
   selected_group_id = request.args.get("group_id")
   view_type = request.args.get("type")  # pending / all / users
#   admin_key = request.args.get("admin_key")
   request_id = request.args.get("request_id")
   requests = []
   request_details = None
   group_member_list = []
   status = request.args.get("status")
   if request_id:
        # success, result = get_request_info(user_id, request_id, admin_key)
        success, result = get_request_info(user_id, request_id)
        if success:
            request_details = result

   target_user_id = request.args.get("target_user_id")
   operator_admin_groups = get_admin_groups(user_id)
   if selected_group_id:
    success, members = group_members(selected_group_id, user_id)
    if success:
        group_member_list = members
    if view_type == "pending":
        # _, requests = get_pending_attack_requests(selected_group_id, user_id, admin_key)
         _, requests = get_pending_attack_requests(selected_group_id, user_id)
    
    elif view_type == "users" and target_user_id:
        _, requests = get_user_requests(
            selected_group_id, user_id, target_user_id)

    elif view_type == "all":
        _, requests = get_all_requests(selected_group_id, user_id, status)

    else:
        requests = []
       
    #     _, requests = get_all_requests(selected_group_id, user_id)
        # elif view_type == "all":
        #     _, requests = get_all_requests(
        #         selected_group_id, user_id, admin_key)
    

   

   return render_template(
       "operatorcontrolpage.html", 
       operator_admin_groups=operator_admin_groups,
        selected_group_id=selected_group_id,
        view_type=view_type,
        requests=requests,
        request_details=request_details,
        group_member_list=group_member_list)
