# sqliRoutes.py

from flask import Blueprint, request, session, jsonify
from datetime import datetime, UTC
from bson import ObjectId
from database import database_name
from .SQLInjectionAttack import sqli_attack

# Blueprint for the SQL injection routes
sqli_bp = Blueprint("sqli_bp", __name__)

# MongoDB collections used in this file
collection_attacks = database_name["attacks"]
collection_targets = database_name["targets"]


# Route to start the SQL injection attack
# Accepts a POST request with a target_id and payload in the request body
@sqli_bp.route("/sqli_start", methods=["POST"])
def sqli_start_attack():

    # Make sure the user is logged in before allowing the attack
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    # Get the user id from the session
    user_id = session["user_id"]

    # Get the JSON data from the request body
    data = request.get_json()

    # Get the target id and payload from the request
    target_id = data.get("target_id")
    sqli_payload = data.get("payload")

    # Make sure both target_id and payload were provided
    if not target_id or not sqli_payload:
        return jsonify({"success": False, "message": "target_id and payload are required."})

    # Look up the target in the MongoDB targets collection
    # The target must belong to the logged in user
    target = collection_targets.find_one({"_id": ObjectId(target_id)})
    if not target:
        return jsonify({"success": False, "message": "Issue with finding target."})

    # Run the SQL injection attack logic with the payload and target config
    # Returns vulnerability result and a log of what happened
    attack_result = sqli_attack(sqli_payload, target)

    # Set the status as Completed since the attack ran successfully
    status = "Completed"

    # Build the attack log document to store in MongoDB
    # This gets logged to the attacks collection and shows up in the reports page
    attack_log = {
        "user_id": ObjectId(user_id),
        "attack_type": "SQL Injection",
        "target_id": ObjectId(target_id),
        "payload": sqli_payload,
        "timestamp": datetime.now(UTC),
        "status": status,
        "vulnerability": attack_result["vulnerability"],
        "attack_sqli_log": attack_result["sqli_log"]
    }

    # Insert the attack log into the MongoDB attacks collection
    doc_result = collection_attacks.insert_one(attack_log)

    # Return the result to the client with the attack id and vulnerability status
    return jsonify({
        "success": True,
        "attack_id": str(doc_result.inserted_id),
        "vulnerability": attack_result["vulnerability"],
        "sqli_log": attack_result["sqli_log"]
    })