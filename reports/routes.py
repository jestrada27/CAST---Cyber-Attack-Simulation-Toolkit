from flask import Blueprint, request, session, jsonify, Flask, redirect, render_template, flash, url_for
#from reporting import getReportsForUser, serialize
from .reports_db import (getReportsForUser, get_filtered_logs, serialize_attack_log, get_all_logs, get_attack_stats, delete_attack as db_delete, 
clear_all_attacks as db_clear, update_report_url, serialize,generate_random_attack, clear_all_periodic as periodic_clear, delete_periodic as db_delete_periodic)
from datetime import datetime
from bson import ObjectId

#reports_bp = Blueprint("reports", __name__, url_prefix="/reports")
reports_bp = Blueprint("reports", __name__)

#route and function for getting the user report
@reports_bp.route("/user_report", methods=["GET"])
def get_user_report():
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
   #based on user_id and gets the reports that are tied to the user
   user_id = session["user_id"]
   user_report = getReportsForUser(user_id)
   
   if not user_report:
      return jsonify({"success": True, "attacks": [], "message": "No attack logs/reports have been generated yet."})

   #user_report = [serialize_attack_log(report) for report in user_report]
   #formats the reports correctly
   user_report = [serialize(report) for report in user_report]

   return jsonify({"success": True, "attacks": user_report})


#route to get the attack logs based on the function. it gets the list of attack logs that are in the db and tied to user
@reports_bp.route("/attack_logs", methods=["GET"])
def get_attack_logs():
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
  #gets all logs for the user
   user_id = session['user_id']
   attack_logs = get_all_logs(user_id)
   
   if not attack_logs:
      return jsonify({"success": False, "attacks": [], "message": "No reports have been generated yet."})
   
   #attack_logs = [serialize_attack_log(attack) for attack in attack_logs]
   #returns the logs 
   return jsonify({"success": True, "attacks": attack_logs})

#route to get the stats about attacks
@reports_bp.route("/attack_stats", methods=["GET"])
def get_stats():
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
   #gets user id and uses function to get the stats and returns stats
   user_id = session['user_id']
   attack_stats = get_attack_stats(user_id)
   return jsonify({"success": True, "stats": attack_stats})
   

#route for deleting an attack when the user wants to delete a specific attack
@reports_bp.route("/delete_attack/<attack_id>", methods=["DELETE"])
def delete_route(attack_id):
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
   #userid is used to go to user and delete function is used to delete the specific attack and then it's returned
   user_id = session["user_id"]
   attack_deleted = db_delete(attack_id, user_id)
   
   return {"success": True, "deleted":attack_deleted, "message": "Attack deleted."}


#Noah
@reports_bp.route("/delete_periodic/<periodic_id>", methods=["DELETE"])
def periodic_delete_route(periodic_id):
   if "user_id" not in session:
      return {"success": False, "message": "Not logged in"}, 401
   
   user_id = session["user_id"]
   periodic_deleted = db_delete_periodic(periodic_id, user_id)

   return {"success": True, "deleted": periodic_deleted, "message": "Periodic Report Deleted"}


#route and function for clearing all the list of attack logs that are tied to the user.
@reports_bp.route("/clear_all_attacks", methods=["DELETE"])
def clear_all_route():
    if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
    #uses userid for user and then uses the clear function to clear all of the attacks. 
    user_id = session['user_id']

    cleared_attacks = db_clear(user_id)
    return {"success": True, "deleted": cleared_attacks, "message": "Cleared."}

#Noah
@reports_bp.route("/clear_all_periodic", methods=["DELETE"])
def clear_periodic_route():
   
   if "user_id" not in session:
      return {"success": False, "message": "Not logged in"}, 401
    
   user_id = session["user_id"]
   cleared_periodic = periodic_clear(user_id)
   return {"success": True, "deleted": cleared_periodic, "message": "Periodic cleared."}


#database route so the database page
@reports_bp.route("/database")
def database_page():
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
   #sets up the database page by getting all logs and attack stats that are shown on the page and renders it
   user_id = session["user_id"]
   logs = get_all_logs(user_id)
   stats = get_attack_stats(user_id)
   periodic_reports = get_periodic(user_id)

   return render_template("database.html", logs=logs, stats=stats, periodic_reports=periodic_reports, username=session["username"])

#route and function for the user to be able to filter and sort the attacks in their list.
@reports_bp.route("/attack_logs/filter", methods=["GET"])
def filter_attack_log():
   if "user_id" not in session:
       return {"success": False, "message": "Not logged in"}, 401
    
   #gets information for the sorting and the filtering for when the route is used
   user_id = session["user_id"]
   attack_type = request.args.get("attack_type")
   status = request.args.get("status")
   #performance = request.args.get("performance")
   sorter = request.args.get("sorter", "Newest")
  
   #uses the information to filter and sort by using the function and then returning filtered logs
   filtered_logs = get_filtered_logs(
      user_id, attack_type=attack_type, status=status,
      sorter=sorter)

   return jsonify({"success": True, "attacks": filtered_logs})

#testing route for the simulate / generate attack to populate db so we can get attack results/reports showing
@reports_bp.route("/simulate_attack", methods=["POST"])
def simulate_attack():

    if "user_id" not in session:
        return jsonify({"success": False}), 401

    generate_random_attack(session["user_id"])

    return jsonify({"success": True})


from database import database_name
report_collection = database_name['reports']
collection_attacks = database_name["attacks"]
from .reports_db import periodic_json, last_periodic_report, json_attack_report, get_periodic, json_periodic_report, periodic_pdf
from flask import send_file
from io import BytesIO
import json
from datetime import datetime

@reports_bp.route("/periodic_data", methods=["GET"])
def periodic_data():
    
   if "user_id" not in session:
      return jsonify({"success": False}), 401
    
   user_id = session["user_id"]
   report_type = request.args.get("report_type")

   # previous_report = report_collection.find_one({
   #    "user_id": ObjectId(user_id), "type": "periodic"
   # }, sort = [("generated_at", -1)])
   previous_report = last_periodic_report(user_id)
   
   user_attacks = {"user_id": ObjectId(user_id)}

   if previous_report:
      user_attacks["timestamp"] = {"$gt": previous_report["generated_at"]}
   

   attacks_list = list(collection_attacks.find(user_attacks))

   #add if statement for checking if there is no attacks done since last report
   if len(attacks_list) == 0:
      return jsonify({"success": False, 
      "message": "No attacks have been conducted for periodic report generation."}), 400
   start_period = previous_report["generated_at"] if previous_report else None
   generated_at = datetime.utcnow()
   end_period = generated_at
   

   result = report_collection.insert_one({
      "user_id": ObjectId(user_id),
      "report": "periodic",
      #"type": report_type,
      "generated_at": generated_at,
      "start_period": start_period,
      "end_period": end_period, 
      "attack_amount": len(attacks_list),
      #"attacks": attacks_list
      "attacks": [str(attack["_id"]) for attack in attacks_list]
   })
   report_id = result.inserted_id

   if report_type == "json":
      file_report = periodic_json(attacks_list, generated_at, start_period, end_period, report_id)

   elif report_type == "pdf":
      file_report = periodic_pdf(attacks_list, generated_at, start_period, end_period, report_id)

   else:
      return jsonify({"success": False, "message": "Failed to generate periodic report."})

   return file_report


@reports_bp.route("/json_report/<attack_id>")
def attack_json_report(attack_id):

   if "user_id" not in session:
      return jsonify({"success": False}), 401
   
   user_id = session["user_id"]
   individual_attack = json_attack_report(attack_id, user_id)

   if not individual_attack:
      return jsonify({"success": False, "message": "JSON Report not found"}), 404
   
   #attack_serial = serialize_attack_log(individual_attack)
   json_byte_data = BytesIO(json.dumps(individual_attack, indent=4, default=str).encode("utf-8"))
   json_byte_data.seek(0)
   # filename = f"{attack_serial['attack_type']}_{attack_serial['time']}_Report.json"
   file_time = individual_attack.get("timestamp")
   if file_time:
      time_format = file_time.strftime('%Y-%m-%d_%H-%M-%S')
   else:
      time_format = "Unknown"
   filename = f"{individual_attack.get('attack_type', 'Attack')}_{time_format}_Report.json"
   #filename = f"{individual_attack.get('attack_type', 'Attack')}_{time_format}_Report"
   return send_file(
      json_byte_data, 
      mimetype="application/json",
      as_attachment=True, 
      download_name=filename
   )
   #return jsonify(attack_serial)
   #return jsonify(individual_attack)


@reports_bp.route("/periodic_json/<report_id>")
def periodic_json_report(report_id):

   if "user_id" not in session:
      return jsonify({"success": False}), 401
   
   user_id = session["user_id"]
   found_report = json_periodic_report(report_id, user_id)

   if not found_report:
      return jsonify({"success": False, "message": "JSON Periodic Report not found"}), 404
   
   attacks_list = list(collection_attacks.find(
      {
         "_id": {"$in": [ObjectId(attacks) for attacks in found_report["attacks"]]}
      }
   ))
   return periodic_json(attacks_list, found_report["generated_at"], found_report.get("start_period"), found_report.get("end_period"), found_report["_id"])
   #return periodic_json(found_report["attacks"], found_report["generated_at"])



@reports_bp.route("/periodic_pdf/<report_id>")
def periodic_pdf_report(report_id):

   if "user_id" not in session:
      return jsonify({"success": False}), 401

   user_id = session["user_id"]
   found_report = json_periodic_report(report_id, user_id)

   if not found_report:
      return jsonify({"success": False, "message": "PDF Periodic Report not found"}), 404
   
   attacks_list = list(collection_attacks.find(
      {
         "_id": {"$in": [ObjectId(attacks) for attacks in found_report["attacks"]]}
      }
   ))

   return periodic_pdf(attacks_list, found_report["generated_at"], found_report.get("start_period"), found_report.get("end_period"), found_report["_id"])