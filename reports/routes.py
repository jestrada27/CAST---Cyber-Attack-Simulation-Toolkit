from flask import Blueprint, request, session, jsonify, Flask, redirect, render_template, flash, url_for
#from reporting import getReportsForUser, serialize
from .reports_db import (getReportsForUser, get_filtered_logs, serialize_attack_log, get_all_logs, get_attack_stats, delete_attack as db_delete, 
                        clear_all_attacks as db_clear, update_report_url, serialize,generate_random_attack)
#reports_bp = Blueprint("reports", __name__, url_prefix="/reports")
reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/user_report", methods=["GET"])
def get_user_report():
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
   
   user_id = session["user_id"]
   user_report = getReportsForUser(user_id)
   
   if not user_report:
      return jsonify({"success": True, "attacks": [], "message": "No attack logs/reports have been generated yet."})

   #user_report = [serialize_attack_log(report) for report in user_report]
   user_report = [serialize(report) for report in user_report]

   return jsonify({"success": True, "attacks": user_report})

#@reports_bp #route for serialize attack log?


@reports_bp.route("/attack_logs", methods=["GET"])
def get_attack_logs():
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
  
   user_id = session['user_id']
   attack_logs = get_all_logs(user_id)
   
   if not attack_logs:
      return jsonify({"success": False, "attacks": [], "message": "No reports have been generated yet."})
   
   #attack_logs = [serialize_attack_log(attack) for attack in attack_logs]

   return jsonify({"success": True, "attacks": attack_logs})


@reports_bp.route("/attack_stats", methods=["GET"])
def get_stats():
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
   
   user_id = session['user_id']
   attack_stats = get_attack_stats(user_id)
   return jsonify({"success": True, "stats": attack_stats})
   


@reports_bp.route("/delete_attack/<attack_id>", methods=["DELETE"])
def delete_route(attack_id):
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
   
   user_id = session["user_id"]
   attack_deleted = db_delete(attack_id, user_id)
   
   return {"success": True, "deleted":attack_deleted, "message": "Attack deleted."}


@reports_bp.route("/clear_all_attacks", methods=["DELETE"])
def clear_all_route():
    if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
    
    user_id = session['user_id']

    cleared_attacks = db_clear(user_id)
    return {"success": True, "deleted": cleared_attacks, "message": "Cleared."}


@reports_bp.route("/database")
def database_page():
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
   
   user_id = session["user_id"]
   logs = get_all_logs(user_id)
   stats = get_attack_stats(user_id)

   return render_template("database.html", logs=logs, stats=stats, username=session["username"])


@reports_bp.route("/attack_logs/filter", methods=["GET"])
def filter_attack_log():
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
    
   user_id = session["user_id"]
   attack_type = request.args.get("attack_type")
   status = request.args.get("status")
   performance = request.args.get("performance")
   sorter = request.args.get("sorter", "Newest")
  
   filtered_logs = get_filtered_logs(
      user_id, attack_type=attack_type, status=status,
      performance=performance, sorter=sorter)

   return jsonify({"success": True, "attacks": filtered_logs})


@reports_bp.route("/simulate_attack", methods=["POST"])
def simulate_attack():

    if "user_id" not in session:
        return jsonify({"success": False}), 401

    generate_random_attack(session["user_id"])

    return jsonify({"success": True})