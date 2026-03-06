from flask import Blueprint, request, session, jsonify
from datetime import datetime
from bson import ObjectId
from database import database_name
from .xss_logic import xss_attack

xss_bp = Blueprint("xss_bp", __name__)

collection_attacks = database_name["attacks"]
collection_targets = database_name["targets"]


@xss_bp.route("/xss_start", methods=["GET"])
def xss_start_attack():
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
    

    user_id = session["user_id"]
    data = request.get_json()

    target_id = data.get("target_id")
    xss_payload = data.get("payload")

    target = collection_targets.find_one({"_id": ObjectId(target_id)})
    #target = collection_targets.find_one({"_id": ObjectId(target_id), "whitelisted": True})
    if not target:
        return jsonify({"success": False, "message": "Issue with finding target."})

    attack_result = xss_attack(xss_payload, target)

    
    status = "Completed"
    attack_log = {
        "user_id": ObjectId(user_id),
        "attack_type": "XSS",
        "target_id": ObjectId(target_id),
        "payload": xss_payload,
        "timestamp": datetime.utcnow(),
        "status": status,
        "vulnerability": attack_result["vulnerability"],
        "attack_xss_log": attack_result["xss_log"]
    }

    doc_result = collection_attacks.inser_one(attack_log)

    return jsonify({
        "success": True,
        "attack_id": str(doc_result.inserted_id),
        "vulnerability": attack_result["vulnerability"]
    })