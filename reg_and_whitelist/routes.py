from flask import Blueprint, request, session, jsonify, Flask, redirect, render_template, flash, url_for
from datetime import datetime
from bson import ObjectId
from .registrate_whitelist import whitelist_target, get_whitelisted_targets

#whitelist and target registration blueprint with imports above
whitelist_bp = Blueprint("target_and_whitelist", __name__)

#route for the target to be whitelisted in the app so that it can be attacked and not if not whitelisted
@whitelist_bp.route("/target_whitelist/<target_id>", methods=["POST"])
def whitelist_target_route(target_id):
    if "username" not in session:
       return {"success": False, "message": "Not logged in"}, 401
    
    #gets the owners username so that it can whitelist the target they made / tied to them
    owner_name = session["username"]
    try:
        #uses the function to whitelist the specfic target based on the di
        whitelisted_target = whitelist_target(target_id, owner_name)
    except:
        return jsonify({"success": False, "message": "Wrong target" })

    #returns what has been updated/whitelisted
    if whitelisted_target.matched_count == 0:
        return jsonify({"success": False, "message": "Target not found"})

    return jsonify({"success": True, "message": "Target has been whitelisted"})


#route for the app to show the list of whitelisted targets
@whitelist_bp.route("/whitelisted_target_list", methods=["POST"])
def whitelisted_list_route():
    if "username" not in session:
       return {"success": False, "message": "Not logged in"}, 401
    
    #gets the owner and then uses the function to show the whitelisted targets by the owner/person who set targets up
    owner_name = session["username"]
    target_list = get_whitelisted_targets(owner_name)

    #formats them correctly and then returns them
    for target in target_list:
        target["_id"] = str(target["_id"])
    return jsonify({"success": True, "target_list": target_list})