
from flask import Blueprint, request, session, jsonify
from datetime import datetime
from bson import ObjectId
from database import database_name
from .operator import (approve_attack, deny_attack, get_pending_attack_requests,
user_cancel_attack, get_all_requests, get_request_info, get_user_requests)


#blueprint for route and database collection data
operator_bp = Blueprint("operator_cntrl_bp", __name__)


@operator_bp.route("/approve/<attack_id>", methods=["POST"])
def approve_attack_route(attack_id): #fix
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    user_id = session["user_id"]
    data = request.get_json()
    admin_key = data.get("admin_key")
    if not admin_key:
        return jsonify({"success": False, "message":"Not admin/no admin key"})

    attack_approved, approve_message = approve_attack(user_id, attack_id, admin_key) #fix
    return jsonify({"success": attack_approved, "message": approve_message})


@operator_bp.route("/deny/<attack_id>", methods=["POST"])
def deny_attack_route(attack_id): #fix
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    user_id = session["user_id"]
    data = request.get_json()
    admin_key = data.get("admin_key")
    if not admin_key:
        return jsonify({"success": False, "message":"Not admin/no admin key"})
    
    attack_denied, deny_message = deny_attack(user_id, attack_id, admin_key) #fix
    return jsonify({"success": attack_denied, "message": deny_message})


@operator_bp.route("/pending_requests/<group_id>", methods=["POST"])
def pending_requests_route(group_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    user_id = session["user_id"]
    data = request.get_json()
    admin_key = data.get("admin_key")
    if not admin_key:
        return jsonify({"success": False, "message":"Not admin/no admin key"})
    
    got_reqeuests, result = get_pending_attack_requests(group_id, user_id, admin_key)

    return jsonify({"success": got_reqeuests, 
                    "request_data": result if got_reqeuests else None,
                    "message": None if got_reqeuests else "Requests not received"
    })


@operator_bp.route("/cancel_attack/<attack_id>", methods=["POST"])
def cancel_request_route(attack_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    user_id = session["user_id"]
    cancelled_request, cancel_message = user_cancel_attack(user_id, attack_id)
    return jsonify({"success": cancelled_request, "message": cancel_message})


@operator_bp.route("/all_requests/all/<group_id>", methods=["POST"])
def get_requests_route(group_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    
    user_id = session["user_id"]
    data = request.get_json()
    admin_key = data.get("admin_key")
    status = data.get("status")
    if not admin_key:
        return jsonify({"success": False, "message":"Not admin/no admin key"})
    
    got_reqeuests, result = get_all_requests(group_id, user_id, admin_key, status)

    return jsonify({"success": got_reqeuests, 
                    "request_data": result if got_reqeuests else None,
                    "message": None if got_reqeuests else "Requests not received"
    })


@operator_bp.route("/info_request/<attack_id>", methods=["POST"])
def request_details_route(attack_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    user_id = session["user_id"]
    data = request.get_json()
    admin_key = data.get("admin_key")
    
    details_requested, result = get_request_info(user_id, attack_id, admin_key)

    return jsonify({"success": details_requested, "data": result})


@operator_bp.route("/user_requests/<group_id>/<target_user_id>", method=["POST"])
def user_requests_route(group_id, target_user_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    
    user_id = session["user_id"]
    data = request.get_json()
    admin_key = data.get("admin_key")
    status = data.get("status")

    if not admin_key:
        return jsonify({"success": False, "message":"Not admin/no admin key"})
    
    user_info_requested, result = get_user_requests(group_id, user_id, target_user_id, admin_key, status)

    return jsonify({"success": user_info_requested, 
                    "request_data": result if user_info_requested else None,
                    "message": None if user_info_requested else "Requests not received"
    })