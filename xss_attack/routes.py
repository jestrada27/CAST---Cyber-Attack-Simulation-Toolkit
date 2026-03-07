from flask import Blueprint, request, session, jsonify
from datetime import datetime
from bson import ObjectId
from database import database_name
from .xss_logic import xss_attack
import time

#blueprint for route and database collection data
xss_bp = Blueprint("xss_bp", __name__)

collection_attacks = database_name["attacks"]
collection_targets = database_name["targets"]

#xss route to start/run the attack if needed
@xss_bp.route("/xss_start", methods=["GET"])
def xss_run_attack():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    
    #get data for user and data for the target and payload
    user_id = session["user_id"]
    data = request.get_json()

    target_id = data.get("target_id")
    xss_payload = data.get("payload")

    ###xss_config = {data.get("payloads"), data.get("xss_type")}

    #find target in db and do xss on target
    target = collection_targets.find_one({"_id": ObjectId(target_id)})
    #target = collection_targets.find_one({"_id": ObjectId(target_id), "whitelisted": True})
    if not target:
        return jsonify({"success": False, "message": "Issue with finding target."})

    attack_result = xss_attack(xss_payload, target)

    #store info in db for the attack log/report 
    status = "Completed"
    attack_log = {
        "user_id": ObjectId(user_id),
        "attack_type": "XSS",
        "target_id": ObjectId(target_id),
        "timestamp": datetime.utcnow(),
        "status": status,
        "report_available": True,
        "report_url": "https://example.com/whitepaper.pdf",
        "payload": xss_payload,
        "xss_attempt": attack_result["xss_attempt"],
        "xss_successful": attack_result["xss_successful"],
        "vulnerability": attack_result["vulnerability"],
        "xss_time": attack_result["xss_time"],
        "attack_xss_log": attack_result["xss_log"],
        #"attack_xss_config": xss_config,
        
    }
    
    doc_result = collection_attacks.insert_one(attack_log)
    #reutrn success if worked
    return jsonify({
        "success": True,
        "attack_id": str(doc_result.inserted_id),
        "vulnerability": attack_result["vulnerability"]
    })