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
@xss_bp.route("/xss_start", methods=["POST"])
def xss_run_attack():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    
    #get data for user and data for the target and payload
    user_id = session["user_id"]
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "JSON Issue"})
    
    target_id = data.get("target_id")
    if not target_id:
        return jsonify({"success": False, "message": "Target ID Issue"})
    try:
        target_id = ObjectId(target_id)
    except: 
        return jsonify({"success": False, "message": "Target ID Issue"})
    
    xss_payload = data.get("payload")
    # if not xss_payload:
    #     return jsonify({"success": False, "message": "Not XSS payload"})
    #xss_config = {data.get("payloads"), data.get("xss_type")}
    xss_config = {"payloads": [xss_payload] if xss_payload else None, "xss_type": data.get("xss_type", "reflected")}

    #find target in db and do xss on target
    #target = collection_targets.find_one({"_id": ObjectId(target_id)})
    target = collection_targets.find_one({"_id": target_id})
    #target = collection_targets.find_one({"_id": ObjectId(target_id), "whitelisted": True})
    if not target:
        return jsonify({"success": False, "message": "Issue with finding target."})

    if "url" not in target: 
        return jsonify({"success": False, "message": "No target URL"})

    #attack_result = xss_attack(xss_payload, target)
    attack_result = xss_attack(target, xss_config)

    #store info in db for the attack log/report 
    status = "Completed"
    attack_log = {
        "user_id": ObjectId(user_id),
        "attack_type": "XSS",
        "target_id": target_id,
        "timestamp": datetime.utcnow(),
        "status": status,
        "report_available": True,
        "report_url": "https://example.com/whitepaper.pdf",
        "payload": xss_payload,
        "xss_attempt": attack_result["attempts"],
        "xss_successful": attack_result["successful_count"],
        "vulnerability": attack_result["vulnerability"],
        "xss_time": attack_result["xss_time"],
        "attack_xss_log": attack_result["xss_log"],
        "attack_xss_config": xss_config
        
    }
    
    doc_result = collection_attacks.insert_one(attack_log)
    #reutrn success if worked
    return jsonify({
        "success": True,
        "attack_id": str(doc_result.inserted_id),
        "vulnerability": attack_result["vulnerability"],
        "xss_log": attack_result["xss_log"]
    })