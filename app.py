from flask import Flask, request, session, redirect, render_template, flash, url_for, jsonify
from flask_mail import Mail, Message
from bson.objectid import ObjectId
from datetime import datetime
import os
import bcrypt
from dotenv import load_dotenv
load_dotenv()
#from datetime import datetime, timedelta
import time
from copy import deepcopy
from itsdangerous import URLSafeTimedSerializer as Serializer

from Attacks.DNSTunnelingExperiment import run_dns_tunneling_experiment
from Attacks.ModuleRunners import run_bruteforce_experiment, run_generic_module_simulation
from Attacks.SafetyEnforcementEngine import (
    SafetyEnforcementEngine,
    build_safety_settings_from_form,
    normalize_safety_settings,
)

#attack
from Attacks.ModuleRunners import run_xss_experiment


# Mongo collections used directly by this module.
from database import database_name

collection_users = database_name["users"]
collection_targets = database_name["targets"]
collection_experiments = database_name["experiments"]
#Noah: added attack log collection and new attack request collection
collection_attacks = database_name["attacks"]
collection_requests = database_name["attack_requests"]

app = Flask(__name__)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
app.secret_key = os.getenv('SECRETKEY')

mail = Mail(app)

from user_management import user_manage_bp
app.register_blueprint(user_manage_bp)

from reports import reports_bp
app.register_blueprint(reports_bp)


# from xss_attack import xss_bp
# app.register_blueprint(xss_bp)
#Noah - setup for blueprints for operator and reg_and_whitelist
from operator_controls import operator_bp
app.register_blueprint(operator_bp)

from reg_and_whitelist import whitelist_bp
app.register_blueprint(whitelist_bp)

#password checking for if the password is a certain length and complexity
def good_password_check(password):
    """Validate password complexity and return an error string or None."""
    lowercase = False
    uppercase = False
    number = False
    special_char = False
    special_char_list = "~`! @#$%^&*()_-+={[}]|:;\"'<,>.?/"

    if len(password) < 7 or len(password) > 40:
        return 'Password needs to be 7-40 characters in length.'

    for char in password:
        if char.islower():
            lowercase = True
        if char.isupper():
            uppercase = True
        if char.isdigit():
            number = True
        if char in special_char_list:
            special_char = True

    if not lowercase or not uppercase or not number or not special_char:
        return 'Password needs 1 lowercase, 1 uppercase, 1 number, and 1 special character.'
    return None


def reset_token(user_id):
    """Create a time-limited password reset token for a user id."""
    serial = Serializer(app.secret_key)
    return serial.dumps(str(user_id), salt="password_reset")


def verify_token(token, max_age=1800):
    """Decode a reset token and return user id if token is valid."""
    serial = Serializer(app.secret_key)
    try:
        user_id = serial.loads(token, salt="password_reset", max_age=max_age)
    except Exception:
        return None
    return user_id


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Accept user email and send reset link when the account exists."""
    if request.method == 'POST':
        email = request.form['email'].strip()
        user = collection_users.find_one({"email": email})
        flash("Password reset link sent to email.", "info")

        if user:
            token = reset_token(user["_id"])
            collection_users.update_one({"_id": user["_id"]}, {"$set": {"reset_token": token}})
            send_reset(user, token)

        return redirect('/forgot_password')

    return render_template('forgotpassword.html')


@app.route('/password_reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Validate reset token and allow the user to set a new password."""
    user_id = verify_token(token)
    if not user_id:
        flash("Reset link invalid.", "danger")
        return redirect('/forgot_password')

    user = collection_users.find_one({"_id": ObjectId(user_id), "reset_token": token})
    if not user:
        flash("Reset link invalid.", "danger")
        return redirect('/forgot_password')

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_pw = request.form['confirm_pw']

        if new_password != confirm_pw:
            flash("Passwords are not the same.", "danger")
            return redirect(request.url)

        bad_password = good_password_check(new_password)
        if bad_password:
            flash(bad_password, 'danger')
            return redirect(request.url)

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        collection_users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"password": hashed_password}, "$unset": {"reset_token": ""}}
        )

        flash("Password updated.", "success")
        return redirect('/')

    return render_template('passwordreset.html', token=token)


def send_reset(user, token):
    """Send the password reset email containing the signed reset link."""
    password_reset_link = url_for('reset_password', token=token, _external=True)
    msg = Message(
        'Password Reset Request for CAST App',
        sender=app.config['MAIL_USERNAME'],
        recipients=[user['email']]
    )
    msg.body = (
        f"Click the link to reset your CAST password: {password_reset_link}\n"
        "Please ignore this email if you did not create the password reset request. Thank you."
    )
    mail.send(msg)


@app.route('/createaccount', methods=['GET', 'POST'])
def create_account():
    """Create a new local account after uniqueness and password checks."""
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_pw = request.form['confirm_pw']

        if len(username) < 5 or len(username) > 30:
            flash('Username needs to be 5-30 characters in length. Please enter a new username.', 'danger')
            return redirect('/createaccount')

        if password != confirm_pw:
            flash('Password not the same', 'danger')
            return redirect('/createaccount')

        if collection_users.find_one({"username": username}):
            flash('User already exists', 'danger')
            return redirect('/createaccount')

        if collection_users.find_one({"email": email}):
            flash('Email already used', 'danger')
            return redirect('/createaccount')

        bad_password = good_password_check(password)
        if bad_password:
            flash(bad_password, 'danger')
            return redirect('/createaccount')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        collection_users.insert_one({
            "username": username,
            "email": email,
            "password": hashed_password
        })

        flash('Account successfully created', 'success')
        return redirect('/')

    return render_template('createaccount.html')


@app.post("/verify-password")
def verify_password():
    """Verify current password before sensitive profile actions."""
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    data = request.get_json() or {}
    entered = data.get("password", "")
    user = collection_users.find_one({"_id": ObjectId(session["user_id"])})

    if not user:
        return {"valid": False}

    if bcrypt.checkpw(entered.encode('utf-8'), user['password']):
        return {"valid": True}

    return {"valid": False}


@app.post("/change-password")
def change_password():
    """Change the authenticated user's password."""
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    data = request.get_json() or {}
    new_pass = data.get("new_password", "")

    bad_password = good_password_check(new_pass)
    if bad_password:
        return {"success": False, "message": bad_password}, 400

    hashed_pass = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt())

    result = collection_users.update_one(
        {"_id": ObjectId(session["user_id"])},
        {"$set": {"password": hashed_pass}}
    )

    return {"success": result.modified_count == 1}


@app.post("/api/change-username")
def change_username():
    """Update username while enforcing uniqueness and length rules."""
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    data = request.get_json() or {}
    new_username = (data.get("username") or "").strip()

    if len(new_username) < 5 or len(new_username) > 30:
        return {"success": False, "message": "Username needs to be 5 to 30 characters long"}

    if not new_username:
        return {"success": False, "message": "Username is required."}, 400

    if new_username == session["username"]:
        return {"success": False, "message": "No change detected"}, 400

    duplicate_check = collection_users.find_one({"username": new_username})
    if duplicate_check:
        return {"success": False, "message": "Username already in use"}, 400

    user_id = ObjectId(session["user_id"])
    old_username = session["username"]
    # Update MongoDB
    result = collection_users.update_one(
        {"_id": user_id},
        {"$set": {"username": new_username}}
    )

    if result.modified_count > 0:
        session["username"] = new_username
    #Noah - fixed change named for username / owner operator control 
        collection_targets.update_many(
            {"owner": old_username},
             {"$set": {"owner": new_username}}
        )

        collection_experiments.update_many(
            {"owner": old_username},
             {"$set": {"owner": new_username}}
        )

    return {"success": result.modified_count == 1}


@app.post("/api/change-email")
def change_email():
    """Update email while enforcing uniqueness and required value."""
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    data = request.get_json() or {}
    new_email = (data.get("email") or "").strip()

    if not new_email:
        return {"success": False, "message": "Email is required."}, 400

    if new_email == session["email"]:
        return {"success": False, "message": "No change detected"}, 400

    duplicate_check = collection_users.find_one({"email": new_email})
    if duplicate_check:
        return {"success": False, "message": "Email already in use"}, 400

    user_id = ObjectId(session["user_id"])
    result = collection_users.update_one(
        {"_id": user_id},
        {"$set": {"email": new_email}}
    )

    if result.modified_count > 0:
        session["email"] = new_email

    return {"success": result.modified_count == 1}


@app.post("/delete-account")
def delete_account():
    """Delete authenticated account and clear current session."""
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    user_id = ObjectId(session["user_id"])
    result = collection_users.delete_one({"_id": user_id})

    session.clear()

    if result.deleted_count == 1:
        return {"success": True}
    return {"success": False, "message": "User not found."}, 404


attempts_num = 6


@app.route('/', methods=['GET', 'POST'])
def user_login():
    """Authenticate user credentials with lockout on repeated failures."""
    if 'attempt' not in session:
        session['attempt'] = 0

    if 'attempt_lock' in session:
        if time.time() < session['attempt_lock']:
            flash('Failed to login after multiple attempts.', 'danger')
            return render_template('login.html')
        session.pop('attempt_lock', None)
        session['attempt'] = 0

    bad_attempt = False
    good_attempt = False

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = collection_users.find_one({"username": username})

        if user:
            database_pw = user['password']
            if bcrypt.checkpw(password.encode('utf-8'), database_pw):
                session["user_id"] = str(user["_id"])
                session["username"] = user["username"]
                session["email"] = user['email']
                good_attempt = True
                flash('Logged in', 'success')
                return redirect('/main_dashboard')
            else:
                bad_attempt = True
                flash('Incorrect login info', 'danger')
                time.sleep(3)
        else:
            bad_attempt = True
            flash('Incorrect login info', 'danger')
            time.sleep(3)

        if bad_attempt:
            session['attempt'] += 1
        elif good_attempt:
            session['attempt'] = 0

        if session['attempt'] >= attempts_num:
            session['attempt_lock'] = time.time() + 30
            flash('Failed to login after multiple attempts. Locked out. Try later.', 'danger')

    return render_template('login.html')


def ensure_user_logged_in():
    """Guard helper: redirect to login when session is missing."""
    if "user_id" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for('user_login'))
    return None


def get_module_label(module_id):
    module_names = {
        "brute force": "Brute Force",
        "xss": "XSS",
        "sqli": "SQL Injection",
        "replay": "Replay",
        "dns": "DNS Tunneling",
    }
    return module_names.get(module_id, module_id.upper() if module_id else "Unknown Module")


def format_timestamp_label(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC")
    return "Unknown time"


def get_risk_band(detectability_score):
    if detectability_score >= 70:
        return "High"
    if detectability_score >= 40:
        return "Moderate"
    return "Low"


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_experiment_results(module_id, raw_results, dry_run=False):
    """Normalize module output so templates and history can render consistently."""
    started_at = raw_results.get("started_at", datetime.utcnow())
    completed_at = raw_results.get("completed_at", datetime.utcnow())

    if module_id == "dns":
        samples = raw_results.get("samples", [])
        avg_throughput = round(safe_float(raw_results.get("avg_throughput_kbps")), 2)
        avg_detectability = round(safe_float(raw_results.get("avg_detectability_score")), 2)
        efficiency = round(avg_throughput / max(avg_detectability, 1), 2)

        return {
            "mode": "Dry Run" if dry_run else "Live Simulation",
            "guidance": raw_results.get("guidance", "DNS tunneling metrics were collected successfully."),
            "sample_count": len(samples),
            "avg_throughput_kbps": avg_throughput,
            "avg_detectability_score": avg_detectability,
            "throughput_detectability_efficiency": efficiency,
            "risk_band": get_risk_band(avg_detectability),
            "samples": samples,
            "started_at": started_at,
            "completed_at": completed_at,
        }

    if module_id == "brute force":
        success_rate = round(safe_float(raw_results.get("success_rate_percent")), 2)
        avg_detectability = round(safe_float(raw_results.get("avg_detectability_score")), 2)
        avg_throughput = round(safe_float(raw_results.get("avg_throughput_kbps")), 2)
        efficiency = round(avg_throughput / max(avg_detectability, 1), 2)

        return {
            "mode": "Dry Run" if dry_run else "Live Simulation",
            "guidance": raw_results.get("guidance", "Brute force telemetry captured successfully."),
            "sample_count": raw_results.get("sample_count", raw_results.get("attempts", 0)),
            "success_rate_percent": success_rate,
            "avg_throughput_kbps": avg_throughput,
            "avg_detectability_score": avg_detectability,
            "throughput_detectability_efficiency": efficiency,
            "risk_band": get_risk_band(avg_detectability),
            "samples": raw_results.get("samples", []),
            "started_at": started_at,
            "completed_at": completed_at,
        }

    avg_detectability = round(safe_float(raw_results.get("avg_detectability_score")), 2)
    avg_throughput = round(safe_float(raw_results.get("avg_throughput_kbps")), 2)
    efficiency = round(avg_throughput / max(avg_detectability, 1), 2)

    return {
        "mode": "Dry Run" if dry_run else "Live Simulation",
        "guidance": raw_results.get("guidance", "Simulation completed."),
        "sample_count": raw_results.get("sample_count", 0),
        "avg_throughput_kbps": avg_throughput,
        "avg_detectability_score": avg_detectability,
        "throughput_detectability_efficiency": efficiency,
        "risk_band": get_risk_band(avg_detectability),
        "samples": raw_results.get("samples", []),
        "started_at": started_at,
        "completed_at": completed_at,
    }


def enrich_experiment(exp, target_map=None):
    """Attach display-friendly fields used by dashboard/history/details."""
    target_map = target_map or {}

    exp["id"] = str(exp["_id"])
    exp["target_name"] = target_map.get(exp.get("target_id"), "Unknown target")
    exp["module_label"] = get_module_label(exp.get("module_id", ""))
    exp["created_at_label"] = format_timestamp_label(exp.get("created_at"))

    results = exp.get("results", {}) or {}
    avg_throughput = round(safe_float(results.get("avg_throughput_kbps")), 2)
    avg_detectability = round(safe_float(results.get("avg_detectability_score")), 2)
    risk_band = results.get("risk_band") or get_risk_band(avg_detectability)

    exp["avg_throughput_kbps"] = avg_throughput
    exp["avg_detectability_score"] = avg_detectability
    exp["risk_band"] = risk_band

    return exp


def get_target_map_for_experiments(experiments):
    target_ids = [exp.get("target_id") for exp in experiments if exp.get("target_id")]
    if not target_ids:
        return {}

    return {
        t["_id"]: t.get("name", "Unknown target")
        for t in collection_targets.find({"_id": {"$in": target_ids}}, {"name": 1})
    }


def get_recent_experiments(owner_username, limit=8):
    """Load recent experiments and attach display-friendly labels."""
    experiments = list(
        collection_experiments
        .find({"owner": owner_username})
        .sort("created_at", -1)
        .limit(limit)
    )

    target_map = get_target_map_for_experiments(experiments)
    for exp in experiments:
        enrich_experiment(exp, target_map)

    return experiments


def get_dashboard_metrics(owner_username):
    experiments = list(collection_experiments.find({"owner": owner_username}))
    throughput_values = []
    detectability_values = []

    for exp in experiments:
        results = exp.get("results", {}) or {}
        throughput = safe_float(results.get("avg_throughput_kbps"), None)
        detectability = safe_float(results.get("avg_detectability_score"), None)

        if throughput is not None:
            throughput_values.append(throughput)
        if detectability is not None:
            detectability_values.append(detectability)

    average_throughput_kbps = round(sum(throughput_values) / len(throughput_values), 2) if throughput_values else 0.0
    average_detectability_score = round(sum(detectability_values) / len(detectability_values), 2) if detectability_values else 0.0

    return average_throughput_kbps, average_detectability_score


def safety_form_state_from_settings(settings):
    """Convert normalized safety settings to template-friendly string values."""
    settings = settings or {}
    authorization = settings.get("authorization", {})
    scope = settings.get("scope", {})
    rate_limit = settings.get("rate_limit", {})
    time_limit = settings.get("time_limit", {})
    monitoring = settings.get("monitoring", {})
    module_constraints = settings.get("module_constraints", {})

    scheduled_end = time_limit.get("scheduled_end")
    if isinstance(scheduled_end, datetime):
        scheduled_end = scheduled_end.strftime("%Y-%m-%dT%H:%M")
    else:
        scheduled_end = ""

    return {
        "approved_users": ", ".join(authorization.get("approved_users", [])),
        "experiment_approved": authorization.get("experiment_approved", False),
        "allowed_ips": ", ".join(scope.get("allowed_ips", [])),
        "allowed_ports": ", ".join(str(port) for port in scope.get("allowed_ports", [])),
        "allowed_urls": ", ".join(scope.get("allowed_urls", [])),
        "allowed_accounts": ", ".join(scope.get("allowed_accounts", [])),
        "allowed_services": ", ".join(scope.get("allowed_services", [])),
        "requests_per_minute": rate_limit.get("requests_per_minute", 60),
        "login_attempts_per_minute": rate_limit.get("login_attempts_per_minute", 20),
        "payloads_per_minute": rate_limit.get("payloads_per_minute", 30),
        "bandwidth_kbps": rate_limit.get("bandwidth_kbps", 256.0),
        "packet_volume_per_minute": rate_limit.get("packet_volume_per_minute", 240),
        "max_duration_seconds": time_limit.get("max_duration_seconds", 90),
        "scheduled_end": scheduled_end,
        "kill_switch_enabled": settings.get("kill_switch", {}).get("enabled", True),
        "max_detectability_score": monitoring.get("max_detectability_score", 80.0),
        "max_scope_violations": monitoring.get("max_scope_violations", 1),
        "max_alerts": monitoring.get("max_alerts", 5),
        "max_unexpected_targets": monitoring.get("max_unexpected_targets", 0),
        "bf_max_attempts_per_account": module_constraints.get("brute force", {}).get("max_attempts_per_account", 5),
        "xss_safe_payloads_only": module_constraints.get("xss", {}).get("safe_payloads_only", True),
        "xss_safe_payloads": ", ".join(module_constraints.get("xss", {}).get("safe_payloads", [])),
        "sqli_probe_only": module_constraints.get("sqli", {}).get("probe_only", True),
        "replay_lab_only": module_constraints.get("replay", {}).get("lab_only", True),
        "replay_max_replays": module_constraints.get("replay", {}).get("max_replays", 10),
        "replay_allow_state_change": module_constraints.get("replay", {}).get("allow_state_changing_methods", False),
        "dns_lab_only": module_constraints.get("dns", {}).get("lab_only", True),
        "dns_max_payload_bytes": module_constraints.get("dns", {}).get("max_payload_bytes", 96),
        "dns_max_queries_per_second": module_constraints.get("dns", {}).get("max_queries_per_second", 5.0),
    }


def target_form_state(target=None):
    """Format stored target settings back into template fields."""
    target = target or {}
    return {
        "name": target.get("name", ""),
        "ip_or_url": target.get("ip_or_url", ""),
        "environment": target.get("environment", "lab"),
        "consent_status": target.get("consent_status", "pending"),
        "allowed_services": ", ".join(target.get("allowed_services", [])),
        "allowed_ports": ", ".join(str(port) for port in target.get("allowed_ports", [])),
        "allowed_accounts": ", ".join(target.get("allowed_accounts", [])),
        "approved_users": ", ".join(target.get("approved_users", [])),
    }


def build_stop_checker(experiment_id, owner_username):
    """Read the persisted kill-switch flag so another request can stop execution."""
    def _checker():
        current = collection_experiments.find_one(
            {"_id": experiment_id, "owner": owner_username},
            {"safety.kill_switch.engaged": 1},
        )
        safety = (current or {}).get("safety", {})
        kill_switch = safety.get("kill_switch", {})
        return bool(kill_switch.get("engaged"))

    return _checker


def prepare_experiment_for_view(experiment):
    """Decorate experiment safety data with display-friendly labels."""
    exp = deepcopy(experiment)
    results = exp.get("results") or {}
    safety_report = results.get("safety_report") or {}
    events = []
    for event in safety_report.get("events", []):
        event_time = event.get("time")
        if isinstance(event_time, datetime):
            event_time_label = event_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            event_time_label = "Unknown time"
        events.append({
            "time_label": event_time_label,
            "decision": event.get("decision", "unknown"),
            "phase": event.get("phase", "runtime"),
            "code": event.get("code", "event"),
            "message": event.get("message", ""),
        })

    safety_report["events_for_view"] = events
    exp["results"] = results
    exp["results"]["safety_report"] = safety_report
    return exp


def derive_run_status(dry_run, safety_summary):
    """Translate a safety summary into an experiment status label."""
    if safety_summary == "Terminated":
        return "Terminated"
    if safety_summary == "Completed With Blocks":
        return "Completed With Blocks"
    if safety_summary == "Completed With Throttling":
        return "Completed With Throttling"
    return "Dry-Run Complete" if dry_run else "Completed"


def status_flash_category(status):
    """Choose a flash category for an execution outcome."""
    if status in {"Terminated", "Failed", "Safety Blocked"}:
        return "danger"
    if status in {"Completed With Blocks", "Completed With Throttling", "Termination Requested"}:
        return "warning"
    return "success"


def run_experiment_now(experiment, target, user):
    """Run an experiment module handler through the safety engine."""
    module_id = experiment.get("module_id")
    attempts = experiment.get("attempts", 5)
    rate_limit = experiment.get("rate_limit", 1.0)
    dry_run = bool(experiment.get("dry_run", True))
    safety_settings = experiment.get("safety") or normalize_safety_settings(
        {},
        module_id=module_id,
        target=target,
        owner_username=user.get("username"),
    )
    safety_engine = SafetyEnforcementEngine(
        experiment=experiment,
        target=target,
        user=user,
        settings=safety_settings,
        stop_checker=build_stop_checker(experiment.get("_id"), experiment.get("owner")),
    )

    authorization = safety_engine.authorize_start()
    if authorization["decision"] in {"blocked", "terminated"}:
        results = {
            "mode": "blocked_before_start",
            "started_at": safety_engine.started_at,
            "completed_at": datetime.utcnow(),
            "sample_count": 0,
            "avg_throughput_kbps": 0.0,
            "avg_detectability_score": 0.0,
            "guidance": authorization["message"],
            "status_counts": {authorization["decision"]: 1},
            "action_events": [{"decision": authorization["decision"], "message": authorization["message"]}],
            "safety_report": safety_engine.build_report(),
            "user_alerts": safety_engine.alerts,
            "safety_summary": safety_engine.final_status(),
        }
        status = "Safety Blocked" if authorization["decision"] == "blocked" else "Terminated"
        return {
            "status": status,
            "results": results,
            "message": authorization["message"],
            "category": status_flash_category(status),
        }

    try:
        if module_id == "dns":
            results = run_dns_tunneling_experiment(
                attempts=attempts,
                rate_limit=rate_limit,
                dry_run=dry_run,
                target=target,
                safety_engine=safety_engine,
            )
            status = derive_run_status(dry_run, results.get("safety_summary"))
            return {
                "status": status,
                "results": results,
                "message": "DNS tunneling simulation finished.",
                "category": status_flash_category(status),
            }

        if module_id == "brute force":
            results = run_bruteforce_experiment(
                attempts=attempts,
                rate_limit=rate_limit,
                dry_run=dry_run,
                target=target,
                safety_engine=safety_engine,
            )
            status = derive_run_status(dry_run, results.get("safety_summary"))
            return {
                "status": status,
                "results": results,
                "message": "Brute force simulation finished.",
                "category": status_flash_category(status),
            }

        if module_id == "xss":
            results = run_xss_experiment(experiment, collection_targets)

            # if your xss result doesn't already include safety_summary,
            # this safely falls back
            status = derive_run_status(
                dry_run,
                results.get("safety_summary") if isinstance(results, dict) else None
            )

            return {
                "status": status,
                "results": results,
                "message": "XSS attack finished.",
                "category": status_flash_category(status),
            }

        if module_id in {"sqli", "replay"}:
            results = run_generic_module_simulation(
                module_id=module_id,
                attempts=attempts,
                rate_limit=rate_limit,
                dry_run=dry_run,
                target=target,
                safety_engine=safety_engine,
            )
            status = derive_run_status(dry_run, results.get("safety_summary"))
            return {
                "status": status,
                "results": results,
                "message": f"{module_id.upper()} simulation finished.",
                "category": status_flash_category(status),
            }
    except Exception as error:
        safety_engine.engage_kill_switch(
            f"Execution failed for module '{module_id}': {error}",
            phase="runtime",
            metadata={"error": str(error)},
        )
        return {
            "status": "Failed",
            "results": {
                "mode": "failed",
                "started_at": safety_engine.started_at,
                "completed_at": datetime.utcnow(),
                "sample_count": 0,
                "avg_throughput_kbps": 0.0,
                "avg_detectability_score": 0.0,
                "guidance": f"Execution failed for module '{module_id}'.",
                "status_counts": {"failed": 1},
                "action_events": [{"decision": "terminated", "message": str(error)}],
                "safety_report": safety_engine.build_report(),
                "user_alerts": safety_engine.alerts,
                "safety_summary": safety_engine.final_status(),
            },
            "message": f"Execution failed for module '{module_id}': {error}",
            "category": "danger",
        }

    return {
        "status": experiment.get("status", "Queued"),
        "results": {
            "mode": "unsupported_module",
            "started_at": safety_engine.started_at,
            "completed_at": datetime.utcnow(),
            "sample_count": 0,
            "avg_throughput_kbps": 0.0,
            "avg_detectability_score": 0.0,
            "guidance": f"Module '{module_id}' runner is not available yet.",
            "status_counts": {"unsupported": 1},
            "action_events": [],
            "safety_report": safety_engine.build_report(),
            "user_alerts": safety_engine.alerts,
            "safety_summary": safety_engine.final_status(),
        },
        "message": f"Module '{module_id}' runner is not available yet.",
        "category": "warning",
    }


@app.route('/main_dashboard')
def main_dashboard():
    """Render dashboard with user summary metrics and recent experiments."""
    if "user_id" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for('user_login'))

    username = session["username"]
    recent_experiments = get_recent_experiments(username, limit=8)
    active_experiment_count = collection_experiments.count_documents({
        "owner": username,
        "status": {"$in": ["Queued", "Running", "Termination Requested"]}
    })
    completed_experiment_count = collection_experiments.count_documents({
        "owner": username,
        "status": {"$in": ["Completed", "Finished", "Success", "Dry-Run Complete", "Completed With Blocks", "Completed With Throttling", "Terminated", "Safety Blocked"]}
    })
    targets_count = collection_targets.count_documents({"owner": username})
    average_throughput_kbps, average_detectability_score = get_dashboard_metrics(username)

    return render_template(
        'Dashboard/maindashboard.html',
        username=username,
        recent_experiments=recent_experiments,
        active_experiment_count=active_experiment_count,
        completed_experiment_count=completed_experiment_count,
        targets_count=targets_count,
        average_throughput_kbps=average_throughput_kbps,
        average_detectability_score=average_detectability_score
    )

@app.route("/experiment_builder", methods=["GET", "POST"])
def experiment_builder():
    """Create a new experiment and optionally execute supported modules."""
    res = ensure_user_logged_in()
    if res is not None:
        return res

    username = session["username"]
    recent_experiments = get_recent_experiments(username, limit=8)
    targets = list(collection_targets.find({"owner": username}, {"name": 1}).sort("created_at", -1))

    modules = [
        {"id": "brute force", "name": "Brute Force (Controlled)"},
        {"id": "xss", "name": "XSS (Safe Test)"},
        {"id": "sqli", "name": "SQL Injection (Safe Probe)"},
        {"id": "replay", "name": "Replay (Simulated)"},
        {"id": "dns", "name": "DNS Tunneling (Lab Simulation)"},
    ]

    source_experiment = None
    source_experiment_id = request.args.get("experiment_id", "")
    if source_experiment_id:
        try:
            source_experiment = collection_experiments.find_one({"_id": ObjectId(source_experiment_id), "owner": username})
        except Exception:
            source_experiment = None

    selected_target_id = request.args.get("target_id", "")
    selected_module_id = request.args.get("module_id", "")
    selected_attempts = request.args.get("attempts", "5")
    selected_rate_limit = request.args.get("rate_limit", "1.0")
    selected_dry_run = request.args.get("dry_run", "true").lower() in ("true", "1", "on", "yes")
    if source_experiment:
        selected_target_id = str(source_experiment.get("target_id", "")) or selected_target_id
        selected_module_id = source_experiment.get("module_id", selected_module_id)
        selected_attempts = str(source_experiment.get("attempts", selected_attempts))
        selected_rate_limit = str(source_experiment.get("rate_limit", selected_rate_limit))
        selected_dry_run = bool(source_experiment.get("dry_run", selected_dry_run))

    selected_target = None
    if selected_target_id:
        try:
            selected_target = collection_targets.find_one({"_id": ObjectId(selected_target_id), "owner": username})
        except Exception:
            selected_target = None

    default_safety_settings = normalize_safety_settings(
        (source_experiment or {}).get("safety"),
        module_id=selected_module_id,
        target=selected_target,
        owner_username=username,
    )
    selected_safety = safety_form_state_from_settings(default_safety_settings)

    if request.method == "POST":
        target_id = request.form.get("target_id")
        module_id = request.form.get("module_id")
        attempts_raw = request.form.get("attempts", "5")
        rate_limit_raw = request.form.get("rate_limit", "1.0")
        dry_run = request.form.get("dry_run") == "on"

        try:
            attempts = int(attempts_raw)
            rate_limit = float(rate_limit_raw)
        except (TypeError, ValueError):
            flash("Attempts and rate limit must be valid numbers.", "danger")
            selected_target = collection_targets.find_one({"_id": ObjectId(target_id), "owner": username}) if ObjectId.is_valid(target_id or "") else None
            selected_safety = safety_form_state_from_settings(build_safety_settings_from_form(request.form, selected_target or {}, username))
            return render_template(
                "experimentbuilder.html",
                username=username,
                targets=targets,
                modules=modules,
                recent_experiments=recent_experiments,
                selected_target_id=target_id or "",
                selected_module_id=module_id or "",
                selected_attempts=attempts_raw,
                selected_rate_limit=rate_limit_raw,
                selected_dry_run=dry_run,
                selected_safety=selected_safety,
            )

        if attempts < 1 or attempts > 50 or rate_limit < 0.1 or rate_limit > 10:
            flash("Use attempts 1-50 and rate_limit 0.1-10.", "danger")
            selected_target = collection_targets.find_one({"_id": ObjectId(target_id), "owner": username}) if ObjectId.is_valid(target_id or "") else None
            selected_safety = safety_form_state_from_settings(build_safety_settings_from_form(request.form, selected_target or {}, username))
            return render_template(
                "experimentbuilder.html",
                username=username,
                targets=targets,
                modules=modules,
                recent_experiments=recent_experiments,
                selected_target_id=target_id or "",
                selected_module_id=module_id or "",
                selected_attempts=attempts,
                selected_rate_limit=rate_limit,
                selected_dry_run=dry_run,
                selected_safety=selected_safety,
            )

        if not target_id or not module_id:
            flash("Please select a target and a module.", "danger")
            selected_target = collection_targets.find_one({"_id": ObjectId(target_id), "owner": username}) if ObjectId.is_valid(target_id or "") else None
            selected_safety = safety_form_state_from_settings(build_safety_settings_from_form(request.form, selected_target or {}, username))
            return render_template(
                "experimentbuilder.html",
                username=username,
                targets=targets,
                modules=modules,
                recent_experiments=recent_experiments,
                selected_target_id=target_id or "",
                selected_module_id=module_id or "",
                selected_attempts=attempts,
                selected_rate_limit=rate_limit,
                selected_dry_run=dry_run,
                selected_safety=selected_safety,
            )

        try:
            target_object_id = ObjectId(target_id)
        except Exception:
            flash("Selected target is invalid.", "danger")
            selected_safety = safety_form_state_from_settings(build_safety_settings_from_form(request.form, {}, username))
            return render_template(
                "experimentbuilder.html",
                username=username,
                targets=targets,
                modules=modules,
                recent_experiments=recent_experiments,
                selected_target_id="",
                selected_module_id=module_id,
                selected_attempts=attempts,
                selected_rate_limit=rate_limit,
                selected_dry_run=dry_run,
                selected_safety=selected_safety,
            )

        target_exists = collection_targets.find_one({"_id": target_object_id, "owner": username}, {"_id": 1, "consent_status": 1}) #noah - finds target
        if not target_exists:
            flash("Selected target was not found for your account.", "danger")
            selected_safety = safety_form_state_from_settings(build_safety_settings_from_form(request.form, {}, username))
            return render_template(
                "experimentbuilder.html",
                username=username,
                targets=targets,
                modules=modules,
                recent_experiments=recent_experiments,
                selected_target_id="",
                selected_module_id=module_id,
                selected_attempts=attempts,
                selected_rate_limit=rate_limit,
                selected_dry_run=dry_run,
                selected_safety=selected_safety,
            )
        
        #Noah - checks for approval if not, means not whitelisted
        if target_exists.get("consent_status") != "approved":
            flash("Target is not whitelisted.", "danger")
        #     return redirect(url_for("experiment_builder"))
        # elif target_exists and target_exists.get("consent_status") == "approved":
        #     flash("Target is whitelisted.", "success")

        description = request.form.get("description", "").strip()
        notes = request.form.get("notes", "").strip()
        try:
            safety_settings = build_safety_settings_from_form(request.form, target_exists, username)
        except (TypeError, ValueError):
            flash("Safety settings contain an invalid numeric value.", "danger")
            selected_safety = safety_form_state_from_settings(build_safety_settings_from_form({}, target_exists, username))
            return render_template(
                "experimentbuilder.html",
                username=username,
                targets=targets,
                modules=modules,
                recent_experiments=recent_experiments,
                selected_target_id=target_id,
                selected_module_id=module_id,
                selected_attempts=attempts,
                selected_rate_limit=rate_limit,
                selected_dry_run=dry_run,
                selected_safety=selected_safety,
            )

        group_id = request.form.get("group_id")
        if not group_id:
            flash("Select group")
            return redirect(url_for("experiment_builder"))
        
        exp_doc = {
            "owner": username,
            "target_id": target_object_id,
            "module_id": module_id,
            "attempts": attempts,
            "rate_limit": rate_limit,
            "dry_run": dry_run,
            "description": description,
            "notes": notes,
            "safety": safety_settings,
            "status": "Queued",
            #"request": "Pending Approval",
            "group_id": ObjectId(group_id),
            "created_at": datetime.utcnow()
        }

        #Noah: added some group collection for document for attacks/experiments
        user_group = collection_users.find_one(
            {"_id": ObjectId(session["user_id"])},
            {"groups": 1},
        ).get("groups", [])
        
        if not collection_users.find_one({
            "_id": ObjectId(session["user_id"]),
            "groups.group_id": ObjectId(group_id)
            }):
            flash("Invalid group selection.", "danger")
            return redirect(url_for("experiment_builder"))
        
        inserted = collection_experiments.insert_one(exp_doc)
        inserted_id = inserted.inserted_id
        
        request_exist_check = collection_requests.find_one({
            "experiment_id": inserted_id
            # "experiment_id": experiment_object_id

        })
        #checks for admin
        is_admin = any(group.get("group_id") == ObjectId(group_id) and group.get("role") == "admin" for group in user_group)
        request_status = "approved" if is_admin else "pending"
        if request_exist_check:
            return False, "Request exists"
        #     collection_requests.insert_one({
        #         "experiment_id": inserted_id,
        #         # {"experiment_id": experiment_object_id}
        #         "group_id": ObjectId(group_id),
        #         "submitted_by":  ObjectId(session["user_id"]),
        #         "username": session["username"],
        #         "status": "pending",
        #         "created_at": datetime.utcnow()
        # })
        else:
        #Noah - inserts info for attack requests 
            collection_requests.insert_one({
                #user_id?
                "experiment_id": inserted_id, 
                "group_id": ObjectId(group_id),
                "submitted_by": ObjectId(session["user_id"]),
                "username": session["username"],
                "status": request_status,
                "created_at": datetime.utcnow()
            })
        # admin check for if admin
        if is_admin:
            flash("Experiment approved - admin detected.")
        else:
            flash("Experiment created. Waiting for approval.", "success")
        return redirect(url_for("experimentdetails", experiment_id=str(inserted_id)))

        # Run the selected module immediately when a runner is available.
        created_exp = collection_experiments.find_one({"_id": inserted_id, "owner": username})
        if created_exp:
            execution = run_experiment_now(created_exp, target_exists, {"username": username})
            collection_experiments.update_one(
                {"_id": inserted_id, "owner": username},
                {"$set": {
                    "status": execution["status"],
                    "results": execution["results"],
                    "safety": execution["results"].get("safety_report", {}).get("settings", safety_settings),
                    "started_at": execution["results"]["started_at"],
                    "completed_at": execution["results"]["completed_at"],
                }},
            )
            flash(execution["message"], execution["category"])
        else:
            flash("Experiment created, but execution context was not found.", "warning")
        return redirect(url_for("experimentdetails", experiment_id=str(inserted_id)))
    
    #Noah: user doc info for tying it to the user based on groups so that it gets name
    user_doc = collection_users.find_one({"_id": ObjectId(session["user_id"])})
    user_groups = user_doc.get("groups", []) 
    for g in user_groups:
        group_doc = database_name["groups"].find_one({"_id": g["group_id"]})
        g["name"] = group_doc["name"] 
    return render_template(
        "experimentbuilder.html",
        username=username,
        targets=targets,
        modules=modules,
        recent_experiments=recent_experiments,
        selected_target_id=selected_target_id,
        selected_module_id=selected_module_id,
        selected_attempts=selected_attempts,
        selected_rate_limit=selected_rate_limit,
        selected_dry_run=selected_dry_run,
        selected_safety=selected_safety,
        #noah: new to get user_groups to builder html
        user_groups=user_groups
    )

@app.route("/experiment_history")
def experiment_history():
    """Search and filter the authenticated user's saved experiments."""
    res = ensure_user_logged_in()
    if res is not None:
        return res

    username = session["username"]

    filters = {
        "q": (request.args.get("q") or "").strip(),
        "module_id": (request.args.get("module_id") or "").strip(),
        "status": (request.args.get("status") or "").strip(),
        "target_id": (request.args.get("target_id") or "").strip(),
        "min_throughput": (request.args.get("min_throughput") or "").strip(),
    }

    mongo_query = {"owner": username}

    if filters["module_id"]:
        mongo_query["module_id"] = filters["module_id"]

    if filters["status"]:
        mongo_query["status"] = filters["status"]

    if filters["target_id"]:
        try:
            mongo_query["target_id"] = ObjectId(filters["target_id"])
        except Exception:
            flash("Invalid target filter ignored.", "warning")

    experiments = list(
        collection_experiments.find(mongo_query).sort("created_at", -1)
    )

    target_map = get_target_map_for_experiments(experiments)
    for exp in experiments:
        enrich_experiment(exp, target_map)

    if filters["q"]:
        q = filters["q"].lower()
        experiments = [
            exp for exp in experiments
            if q in (exp.get("description", "") or "").lower()
            or q in (exp.get("notes", "") or "").lower()
            or q in (exp.get("module_label", "") or "").lower()
            or q in (exp.get("target_name", "") or "").lower()
        ]

    if filters["min_throughput"]:
        min_throughput = safe_float(filters["min_throughput"], 0.0)
        experiments = [
            exp for exp in experiments
            if safe_float(exp.get("avg_throughput_kbps"), 0.0) >= min_throughput
        ]

    throughput_values = [safe_float(exp.get("avg_throughput_kbps"), 0.0) for exp in experiments]
    detectability_values = [safe_float(exp.get("avg_detectability_score"), 0.0) for exp in experiments]

    summary = {
        "total": len(experiments),
        "avg_throughput": round(sum(throughput_values) / len(throughput_values), 2) if throughput_values else 0.0,
        "avg_detectability": round(sum(detectability_values) / len(detectability_values), 2) if detectability_values else 0.0,
        "high_risk": sum(1 for exp in experiments if exp.get("risk_band") == "High"),
    }

    targets_list = list(collection_targets.find({"owner": username}).sort("created_at", -1))
    module_choices = [
        ("brute force", "Brute Force"),
        ("dns", "DNS Tunneling"),
        ("sqli", "SQL Injection"),
        ("xss", "XSS"),
        ("replay", "Replay"),
    ]
    status_choices = [
        "Queued",
        "Running",
        "Completed",
        "Dry-Run Complete",
        "Failed",
    ]

    return render_template(
        "experiment_history.html",
        username=username,
        experiments=experiments,
        filters=filters,
        summary=summary,
        targets=targets_list,
        module_choices=module_choices,
        status_choices=status_choices,
    )


@app.route("/targets", methods=["GET", "POST"])
def targets():
    """Create and list per-user authorized test targets."""
    res = ensure_user_logged_in()
    if res is not None:
        return res
    from reg_and_whitelist.registrate_whitelist import target_validation, target_by_status_list #Noah: gets functions from blueprint
    username = session["username"]

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        ip_or_url = (request.form.get("ip_or_url") or "").strip()
        environment = (request.form.get("environment") or "lab").strip().lower()
        consent_status = (request.form.get("consent_status") or "pending").strip().lower()
        allowed_services = [service.lower() for service in (request.form.get("allowed_services") or "").replace(";", ",").split(",") if service.strip()]
        approved_users = [user.strip() for user in (request.form.get("approved_users") or username).replace(";", ",").split(",") if user.strip()]
        allowed_accounts = [account.strip() for account in (request.form.get("allowed_accounts") or "").replace(";", ",").split(",") if account.strip()]

        allowed_ports = []
        for entry in (request.form.get("allowed_ports") or "").replace(";", ",").split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                allowed_ports.append(int(entry))
            except ValueError:
                flash("Allowed ports must be comma-separated numbers.", "danger")
                targets_list = list(collection_targets.find({"owner": username}).sort("created_at", -1))
                return render_template(
                    "targets.html",
                    username=username,
                    targets=targets_list,
                    form_state=target_form_state({
                        "name": name,
                        "ip_or_url": ip_or_url,
                        "environment": environment,
                        "consent_status": consent_status,
                        "allowed_services": allowed_services,
                        "allowed_ports": [],
                        "allowed_accounts": allowed_accounts,
                        "approved_users": approved_users,
                    }),
                )

        if not name or not ip_or_url:
            flash("name and ip_or_url are required.", "danger")
            targets_list = list(collection_targets.find({"owner": username}).sort("created_at", -1))
            return render_template(
                "targets.html",
                username=username,
                targets=targets_list,
                form_state=target_form_state({
                    "name": name,
                    "ip_or_url": ip_or_url,
                    "environment": environment,
                    "consent_status": consent_status,
                    "allowed_services": allowed_services,
                    "allowed_ports": allowed_ports,
                    "allowed_accounts": allowed_accounts,
                    "approved_users": approved_users,
                }),
            )
        
        #if not name or not ip_or_url: #Noah - checks for valid target using target validation
        valid_target, message = target_validation(name, ip_or_url, username)
        if not valid_target:
            #flash("name and ip_or_url are required.", "danger")
            flash(message, "danger")
            return redirect(url_for("targets"))

        # per-user uniqueness (same owner can't create same name twice)
        if collection_targets.find_one({"owner": username, "name": name}):
            flash("target name already exists for your account.", "danger")
            targets_list = list(collection_targets.find({"owner": username}).sort("created_at", -1))
            return render_template(
                "targets.html",
                username=username,
                targets=targets_list,
                form_state=target_form_state({
                    "name": name,
                    "ip_or_url": ip_or_url,
                    "environment": environment,
                    "consent_status": consent_status,
                    "allowed_services": allowed_services,
                    "allowed_ports": allowed_ports,
                    "allowed_accounts": allowed_accounts,
                    "approved_users": approved_users,
                }),
            )

            # return redirect(url_for("targets"))
        #Noah: added params for integration
        # param = (request.form.get("param") or "q").strip()
        # method = (request.form.get("method") or "GET").upper()
        # collection_targets.insert_one({
        #     "owner": username,
        #     "name": name,
        #     "ip_or_url": ip_or_url,
        #     # "param": param,
        #     # "method": method,
        #     "consent_status": "pending",
        #     "created_at": datetime.utcnow()
        # })
        collection_targets.insert_one({
            "owner": username,
            "name": name,
            "ip_or_url": ip_or_url,
            "environment": environment,
            "consent_status": "pending",   
            "allowed_services": allowed_services,
            "allowed_ports": allowed_ports,
            "allowed_accounts": allowed_accounts,
            "approved_users": approved_users,
            "created_at": datetime.utcnow()
        })

        flash("target added!", "success")
        return redirect(url_for("targets"))

    targets_list = list(collection_targets.find({"owner": username}).sort("created_at", -1))
    whitelisted_targets = [target for target in targets_list if target.get("consent_status") == "approved"]
    target_statuses = target_by_status_list(username)
    return render_template("targets.html", username=username, targets=targets_list, form_state=target_form_state({"approved_users": [username]}), whitelisted_targets=whitelisted_targets, target_statuses=target_statuses)
    


@app.route("/experimentdetails/<experiment_id>")
def experimentdetails(experiment_id):
    """Show one experiment only if it belongs to the logged-in user."""
    res = ensure_user_logged_in()
    if res is not None:
        return res

    username = session["username"]

    try:
        experiment_object_id = ObjectId(experiment_id)
    except Exception:
        flash("invalid experiment id", "danger")
        return redirect(url_for("main_dashboard"))

    exp = collection_experiments.find_one({"_id": experiment_object_id, "owner": username})
    if not exp:
        flash("experiment not found", "danger")
        return redirect(url_for("main_dashboard"))
    #Noah: makes results none for page if needed
    if "results" not in exp:
        exp["results"] = None

    target = collection_targets.find_one({"_id": exp["target_id"]})
    target_name = target["name"] if target else "unknown target"
    recent_experiments = get_recent_experiments(username, limit=8)
    #Noah: fixes group name for experiment details
    group_name = ""
    if exp.get("group_id"):
        group_doc = database_name["groups"].find_one({"_id": exp["group_id"]}, {"name": 1})
        if group_doc:
            group_name = group_doc.get("name", "Unknown")

    # Noah - gets the request doc and formats it correctly
    request_doc = collection_requests.find_one({"experiment_id": experiment_object_id, 
    "group_id": exp.get("group_id")})
    if request_doc:
        request_doc["_id"] = str(request_doc["_id"])

    enrich_experiment(exp, {exp.get("target_id"): target_name})
    exp = prepare_experiment_for_view(exp)

    return render_template(
        "experimentdetails.html",
        exp=exp,
        target=target or {},
        target_name=target_name,
        #noah: experiment details name
        group_name=group_name,
        username=username,
        recent_experiments=recent_experiments,
        request_doc=request_doc
    )


@app.post("/experiments/<experiment_id>/start")
def start_experiment(experiment_id):
    """Manual trigger for rerunning supported experiment modules."""
    res = ensure_user_logged_in()
    if res is not None:
        return res

    username = session["username"]

    try:
        experiment_object_id = ObjectId(experiment_id)
    except Exception:
        flash("invalid experiment id", "danger")
        return redirect(url_for("main_dashboard"))

    exp = collection_experiments.find_one({"_id": experiment_object_id, "owner": username})
    if not exp:
        flash("experiment not found", "danger")
        return redirect(url_for("main_dashboard"))

    target = collection_targets.find_one({"_id": exp["target_id"], "owner": username})
    if not target:
        flash("target not found for this experiment", "danger")
        return redirect(url_for("experimentdetails", experiment_id=experiment_id))

    collection_experiments.update_one(
        {"_id": experiment_object_id, "owner": username},
        {"$set": {"status": "Running", "started_at": datetime.utcnow()}},
    )

    latest_exp = collection_experiments.find_one({"_id": experiment_object_id, "owner": username})
    execution = run_experiment_now(latest_exp, target, {"username": username})
    update_doc = {
        "status": execution["status"],
        "results": execution["results"],
        "safety": execution["results"].get("safety_report", {}).get("settings", exp.get("safety")),
        "started_at": execution["results"]["started_at"],
        "completed_at": execution["results"]["completed_at"],
    }
    collection_experiments.update_one(
        {"_id": experiment_object_id, "owner": username},
        {"$set": update_doc},
    )
    if execution["results"]:
        collection_attacks.insert_one({
        "user_id": ObjectId(session["user_id"]),
        "experiment_id": experiment_object_id,
        "attack_type": execution["results"].get("attack_type") or exp.get("module_id"),
        "timestamp": datetime.utcnow(),
        "status": execution["status"],
        "report_available": True,
        "report_url": "https://example.com/whitepaper.pdf",
        "details": execution["results"]
    })
        
    user_request = collection_requests.find_one({
        "experiment_id": experiment_object_id,
        "group_id": exp.get("group_id"),
    })

    #Noah: updates request to failed or completed if done
    # if user_request:
    #     new_status = "completed" if ok else "failed"
    if user_request:
        request_status = (
            "completed" if execution["status"] not in ["Failed", "Safety Blocked", "Terminated"] else "failed"
        )
        
        collection_requests.update_one(
            {"_id": user_request["_id"]},
            {"$set": {"status": request_status}}
        )


    flash(execution["message"], execution["category"])

    return redirect(url_for("experimentdetails", experiment_id=experiment_id))


@app.post("/experiments/<experiment_id>/kill_switch")
def trigger_experiment_kill_switch(experiment_id):
    """Manually engage the experiment kill switch."""
    res = ensure_user_logged_in()
    if res is not None:
        return res

    username = session["username"]
    try:
        experiment_object_id = ObjectId(experiment_id)
    except Exception:
        flash("invalid experiment id", "danger")
        return redirect(url_for("main_dashboard"))

    exp = collection_experiments.find_one({"_id": experiment_object_id, "owner": username})
    if not exp:
        flash("experiment not found", "danger")
        return redirect(url_for("main_dashboard"))
    #Noah: gets user and group info before running attack
    user_doc = collection_users.find_one({"_id": ObjectId(session["user_id"])}, {"groups": 1})
    user_groups = user_doc.get("groups", [])

# Noah: Checks if user is admin in this group
    is_admin = any(g.get("group_id") == exp.get("group_id") and g.get("role") == "admin" for g in user_groups)

# Noah: Gets experiment request
    user_request = collection_requests.find_one({
        "experiment_id": experiment_object_id,
        "group_id": exp.get("group_id")
})


    if not is_admin and (not user_request or user_request.get("status") not in ["approved", "completed"]):
        flash("Experiment not approved.", "danger")
        return redirect(url_for("experimentdetails", experiment_id=experiment_id))
    # user_request = collection_requests.find_one({
    #     "experiment_id": experiment_object_id,
    #     "group_id": exp["group_id"]
    # })
    # if not user_request or user_request.get("status") != "approved":
    #     print("Not approved")
    #     flash("Experment not approved.", "danger")
    #     return redirect(url_for("experimentdetails", experiment_id=experiment_id))

    #Noah - gets target in the database
    target_exists = collection_targets.find_one({
        "_id": exp["target_id"],
        "owner": username
    }, {"consent_status": 1})

    #if doesnt exist goes back to experimentdetails
    if not target_exists:
        flash("Target no longer exists.", "danger")
        return redirect(url_for("experimentdetails", experiment_id=experiment_id))
    #if not approved then cant, else if then its approved
    if target_exists.get("consent_status") != "approved":
        flash("Target is not whitelisted.", "danger")
        return redirect(url_for("experimentdetails", experiment_id=experiment_id))

    # if not target_exists or target_exists.get("consent_status") != "approved":
    #     flash("Target is not whitelisted.", "danger")
    #     return redirect(url_for("experimentdetails", experiment_id=experiment_id))
    elif target_exists and target_exists.get("consent_status") == "approved":
        flash("Target is whitelisted.", "success")


    reason = (request.form.get("reason") or "Emergency stop requested by operator.").strip()
    collection_experiments.update_one(
        {"_id": experiment_object_id, "owner": username},
        {
            "$set": {
                "status": "Termination Requested",
                "safety.kill_switch.engaged": True,
                "safety.kill_switch.reason": reason,
                "safety.kill_switch.engaged_at": datetime.utcnow(),
            }
        },
    )
    flash("Kill switch engaged. Active modules will stop at the next safety checkpoint.", "warning")
    return redirect(url_for("experimentdetails", experiment_id=experiment_id))


@app.get("/experiments/<experiment_id>/safety_report")
def experiment_safety_report(experiment_id):
    """Return the stored safety report for an experiment."""
    res = ensure_user_logged_in()
    if res is not None:
        return res

    username = session["username"]
    try:
        experiment_object_id = ObjectId(experiment_id)
    except Exception:
        return jsonify({"success": False, "message": "invalid experiment id"}), 400

    exp = collection_experiments.find_one({"_id": experiment_object_id, "owner": username})
    if not exp:
        return jsonify({"success": False, "message": "experiment not found"}), 404

    report = (exp.get("results") or {}).get("safety_report")
    if not report:
        return jsonify({"success": False, "message": "no safety report recorded yet"}), 404

    exp = prepare_experiment_for_view(exp)
    return jsonify({
        "success": True,
        "experiment_id": experiment_id,
        "status": exp.get("status"),
        "summary": exp.get("results", {}).get("safety_report", {}).get("summary"),
        "user_alerts": exp.get("results", {}).get("safety_report", {}).get("user_alerts", []),
        "decision_counts": exp.get("results", {}).get("safety_report", {}).get("decision_counts", {}),
        "events": exp.get("results", {}).get("safety_report", {}).get("events_for_view", []),
    })


@app.route('/profile')
def profile():
    """Render the logged-in user's profile view."""
    res = ensure_user_logged_in()
    if res is None:
        user = {
            "username": session["username"],
            "email": session["email"]
        }
        res = render_template('profile.html', user=user)
    return res


@app.route('/logout')
def logout():
    """Clear session and return user to login screen."""
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('user_login'))


if __name__ == '__main__':
    app.run(debug=True)