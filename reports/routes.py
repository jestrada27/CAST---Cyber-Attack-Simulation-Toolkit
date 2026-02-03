from flask import Blueprint, request, session, jsonify, Flask, redirect, render_template, flash, url_for
from reporting import getReportsForUser, serialize
reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/user_report", methods=["GET"])
def get_user_report():
    if "user" not in session:
        return {"success": False, "message": "Not logged in"}, 401
     
    user_id = session["user_id"]
    user_report = getReportsForUser(user_id)
    user_report = [serialize(report) for report in user_report]

    return jsonify({"success": True, "reports": user_report})
