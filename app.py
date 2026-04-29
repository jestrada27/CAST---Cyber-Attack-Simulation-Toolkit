from flask import Flask, request, session, redirect, render_template, flash, url_for, jsonify
from flask_mail import Mail, Message
#from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
import os
import bcrypt
from copy import deepcopy
#from dotenv import load_dotenv
#from datetime import datetime, timedelta
import time
from bson import ObjectId
from itsdangerous import URLSafeTimedSerializer as Serializer
from Attacks.DNSTunnelingExperiment import run_dns_tunneling_experiment
from Attacks.ModuleRunners import run_bruteforce_experiment, run_generic_module_simulation
from Attacks.SafetyEnforcementEngine import (
    SafetyEnforcementEngine,
    build_safety_settings_from_form,
    normalize_safety_settings,
)


# Mongo collections used directly by this module.
from database import database_name
collection_users = database_name["users"]
collection_targets = database_name["targets"]
collection_experiments = database_name["experiments"]

app = Flask(__name__)
#Setting up the mail server that is used for sending the user their reset password link
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
app.secret_key = os.getenv('SECRETKEY')
mail = Mail(app)

#registering the user_management and reports / logs with app.py so they can be used when running the app
from user_management import user_manage_bp
app.register_blueprint(user_manage_bp)

from reports import reports_bp
app.register_blueprint(reports_bp)


#password checking for if the password is a certain length and complexity
def good_password_check(password):
    """Validate password complexity and return an error string or None."""
    #len greater than 7 and less than 40, 1 lowercase, 1 uppercase, 1 number, and 1 special character ~`! @#$%^&*()_-+={[}]|\:;\"'<,>.?/ allowed 
    lowercase = False
    uppercase = False
    number = False
    special_char = False
    special_char_list = "~`! @#$%^&*()_-+={[}]|:;\"'<,>.?/"
    
    #checks password if it's in the charatcer range
    if len(password) < 7 or len(password) > 40:
        return 'Password needs to be 7-40 characters in length.'
        #flash('Password needs to be 7-40 characters in length.', 'danger')
        #return redirect('/createaccount')
    #loops through password to see if there are lowercase, uppercase, digits, or special characters
    for char in password: 
        if char.islower():
            lowercase = True
        if char.isupper():
            uppercase = True
        if char.isdigit():
            number = True
        if char in special_char_list:
            special_char = True

    if lowercase == False or uppercase == False or number == False or special_char == False:
        return 'Password needs 1 lowercase, 1 uppercase, 1 number, and 1 special character.'
        #flash('Password needs 1 lowercase, 1 uppercase, 1 number, and 1 special character.', 'danger')
        #return redirect('/createaccount')
    return None

#token function that is used to create the token for the user to be able to reset their password.
def reset_token(user_id):
    """Create a time-limited password reset token for a user id."""
    #serial = Serializer(app.config['SECRETKEY'], expiration=expiration)
#creation of the reset token using Serializer
    serial = Serializer(app.secret_key)
    return serial.dumps(str(user_id), salt="password_reset")


#function to verify the reset token and that was generated with the Serializer
#loads and checks to see if a token for the user was created and makes sure
def verify_token(token, max_age=1800):
    """Decode a reset token and return user id if token is valid."""
    serial = Serializer(app.secret_key)
    try: 
        user_id = serial.loads(token, salt="password_reset", max_age=max_age)
    except: 
        return None
    return user_id


#forgot password route. used for getting the user to the forgot password page.
#allows the user to enter their email and checks for that email in the database
#if found, the user gets sent a reset token in a link to their email
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


##password reset route for when the user clicks on the reset link. Checks if the user is valid and has a valid token.
#lets the user input their new password and checks if it's good. 
#hashes the password, stores it in the db, and then takes the user back to the login page
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
        collection_users.update_one({"_id": ObjectId(user_id)}, {"$set": {"password": hashed_password}, "$unset": {"reset_token": ""}})

        flash("Password updated.", "success")
        return redirect('/')
    
    return render_template('passwordreset.html', token=token)


#function for sending the user their reset token. creates the url with a message and sends it to the user
def send_reset(user, token):
    """Send the password reset email containing the signed reset link."""
    #token = user_id.reset_token()
    password_reset_link = url_for('reset_password', token=token, _external=True)
    msg = Message('Password Reset Request for CAST App',   
                sender=app.config['MAIL_USERNAME'], recipients=[user['email']])
    msg.body = f'''Click the link to reset your CAST password: {password_reset_link}
    Please ignore this email if you did not create the password reset request. Thank you.'''

    mail.send(msg)


#createaccount

@app.route('/createaccount', methods=['GET', 'POST'])
def create_account():
    """Create a new local account after uniqueness and password checks."""
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_pw = request.form['confirm_pw']

        #username checking for a certain length when creating the account
        if len(username) < 5 or len(username) > 30:
            flash('Username needs to be 5-30 characters in length. Please enter a new username.', 'danger')
            return redirect('/createaccount')

        if password != confirm_pw:
            flash('Password not the same', 'danger' )
            return redirect('/createaccount')
        
        if collection_users.find_one({"username": username}):
            flash('User already exists', 'danger')
            return redirect('/createaccount')

        if collection_users.find_one({"email": email}):
            flash('Email already used', 'danger')
            return redirect('/createaccount')
        
        #checks if the entered password meets the requirements in the good password function. if it doesn't you have to try again.
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
    data = request.get_json()
    entered = data["password"]

    # user = collection_users.find_one(
    #     {"username": session["user"]}
    # )
    user = collection_users.find_one({"_id": ObjectId(session["user_id"])})

    if bcrypt.checkpw(entered.encode('utf-8'), user['password']):
        return {"valid": True}

    return {"valid": False}

@app.post("/change-password")
def change_password():
    """Change the authenticated user's password."""
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401
     
    data = request.get_json()
    new_pass = data["new_password"]

    #new password check for security improvement and for password rules. checks if the changed password meets rules. - Noah
    bad_password = good_password_check(new_pass)
    if bad_password:
            return {"success": False, "message": bad_password}, 400


    # Hash password
    hashed_pass = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt())

    # Update MongoDB
    result = collection_users.update_one(
        #{"username": session["user"]},
        {"_id": ObjectId(session["user_id"])},
        {"$set": {"password": hashed_pass}}
    )

    return {"success": result.modified_count == 1}

@app.post("/api/change-username")
def change_username():
    """Update username while enforcing uniqueness and length rules."""
    #if "user" not in session:
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    data = request.get_json() or {}
    new_username = (data.get("username") or "").strip()

    #Check new username for username rules. makes sure it meets the rule set. - Noah
    if len(new_username) < 5 or len(new_username) > 30:
        return {"success": False, "message": "Username needs to be 5 to 30 characters long"}


    if not new_username:
        return {"success": False, "message": "Username is required."}, 400

    #Make sure the username actaully changed from previous
    #if new_username == session["user"]:
    if new_username == session["username"]:
        return {"success": False, "message": "No change detected"}, 400

    # Make sure that the new username isnt already in use
    duplicate_check = collection_users.find_one({"username": new_username})

    if duplicate_check:
        return {"success": False, "message": "Username already in use"}, 400
    user_id = ObjectId(session["user_id"])
    # Update MongoDB
    result = collection_users.update_one(
        #{"username": session["user"]},
        {"_id": user_id},
        {"$set": {"username": new_username}}
    )

    if result.modified_count > 0:
        #update the local session
        session["username"] = new_username

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

    # Make sure the username actaully changed from previous
    # if new_email == session["user"]:
    if new_email == session["email"]:
        return {"success": False, "message": "No change detected"}, 400

    # Make sure that the new username isnt already in use
    duplicate_check = collection_users.find_one({"email": new_email})

    if duplicate_check:
        return {"success": False, "message": "Email already in use"}, 400
    user_id = ObjectId(session["user_id"])
    # Update MongoDB
    result = collection_users.update_one(
        #{"username": session["user"]},
        {"_id": user_id},
        {"$set": {"email": new_email}}
    )

    if result.modified_count > 0:
        #update the local session
        session["email"] = new_email

    return {"success": result.modified_count == 1}

@app.post("/delete-account")
def delete_account():
    """Delete authenticated account and clear current session."""
    if "user_id" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    #username = session["user"]
    user_id = ObjectId(session["user_id"])
    #result = collection_users.delete_one({"username": username})
    result = collection_users.delete_one({"_id": user_id})

    # Clear session
    session.clear()

    if result.deleted_count == 1:
        return {"success": True}
    else:
        return {"success": False, "message": "User not found."}, 404



#userlogin

#limiting number of login attempts for user to have for logging in
attempts_num = 6

@app.route('/', methods=['GET', 'POST'])
def user_login():
    """Authenticate user credentials with lockout on repeated failures."""

    #set user attempt
    if 'attempt' not in session:
        session['attempt'] = 0
    
    if 'attempt_lock' in session:
        if time.time() < session['attempt_lock']:
            flash('Failed to login after multiple attempts.', 'danger')
            return render_template('login.html')
        else:
            session.pop('attempt_lock', None)
            session['attempt'] = 0

    bad_attempt = False
    good_attempt = False

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        #user = collection_users.find_one({"username": username, "password": password})
        user = collection_users.find_one({"username": username})

        if user:
            #database_user = user['username']
            database_pw = user['password']
            if bcrypt.checkpw(password.encode('utf-8'), database_pw):
                #session["user"] = database_user
                session["user_id"] = str(user["_id"])
                session["username"] = user["username"]
                #session["user"] = database_user
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

        if bad_attempt == True:
            session['attempt'] += 1
        elif good_attempt == True:
            session['attempt'] = 0
        
        if session['attempt'] >= attempts_num:
            session['attempt_lock'] = time.time() + 30
            flash('Failed to login after multiple attempts. Locked out. Try later.', 'danger')
    

    return render_template('login.html')

#Checks to see if the user is logged in. If they are not, we return the redirect response. If they are logged in,
#we return None
def ensure_user_logged_in():
    """Guard helper: redirect to login when session is missing."""
    #if "user" not in session:
    if "user_id" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for('user_login'))
    return None


def get_recent_experiments(owner_username, limit=8):
    """Load recent experiments and attach display-friendly labels."""
    module_names = {
        "brute force": "Brute Force",
        "xss": "XSS",
        "sqli": "SQL Injection",
        "replay": "Replay",
        "dns": "DNS Tunneling",
    }

    experiments = list(
        collection_experiments
        .find({"owner": owner_username})
        .sort("created_at", -1)
        .limit(limit)
    )

    target_ids = [exp.get("target_id") for exp in experiments if exp.get("target_id")]
    target_map = {
        t["_id"]: t.get("name", "Unknown target")
        for t in collection_targets.find({"_id": {"$in": target_ids}}, {"name": 1})
    } if target_ids else {}

    for exp in experiments:
        exp["id"] = str(exp["_id"])
        exp["target_name"] = target_map.get(exp.get("target_id"), "Unknown target")
        module_id = exp.get("module_id", "")
        exp["module_label"] = module_names.get(module_id, module_id.upper() if module_id else "Unknown Module")
        created_at = exp.get("created_at")
        exp["created_at_label"] = created_at.strftime("%Y-%m-%d %H:%M UTC") if isinstance(created_at, datetime) else "Unknown time"

    return experiments


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
        if module_id == "sqli":
            results = run_sqli_experiment(dry_run=dry_run)
            status = "Dry-Run Complete" if dry_run else "Completed"
            return True, status, results, "SQL injection simulation finished"
        if module_id in {"xss", "replay"}:
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

#maindashboard

@app.route('/main_dashboard')
def main_dashboard():
    """Render dashboard with user summary metrics and recent experiments."""

    #if "user" not in session:
    if "user_id" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for('user_login'))

    #username = session["user"]
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

    return render_template(
        'Dashboard/maindashboard.html',
        username=username,
        recent_experiments=recent_experiments,
        active_experiment_count=active_experiment_count,
        completed_experiment_count=completed_experiment_count,
        targets_count=targets_count
    )

#experiment builder
@app.route("/experiment_builder", methods=["GET", "POST"])
def experiment_builder():
    """Create a new experiment and optionally execute supported modules."""
    res = ensure_user_logged_in()
    if res is not None:
        return res

    username = session["username"]
    recent_experiments = get_recent_experiments(username, limit=8)
    targets = list(collection_targets.find({"owner": username}))

    # Module list
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

        target_exists = collection_targets.find_one({"_id": target_object_id, "owner": username})
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
            "created_at": datetime.utcnow()
        }

        inserted = collection_experiments.insert_one(exp_doc)
        inserted_id = inserted.inserted_id

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
    )

@app.route("/targets", methods=["GET", "POST"])
def targets():
    """Create and list per-user authorized test targets."""
    res = ensure_user_logged_in()
    if res is not None:
        return res

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

        collection_targets.insert_one({
            "owner": username,
            "name": name,
            "ip_or_url": ip_or_url,
            "environment": environment,
            "consent_status": consent_status,
            "allowed_services": allowed_services,
            "allowed_ports": allowed_ports,
            "allowed_accounts": allowed_accounts,
            "approved_users": approved_users,
            "created_at": datetime.utcnow()
        })

        flash("target added!", "success")
        return redirect(url_for("targets"))

    targets_list = list(collection_targets.find({"owner": username}).sort("created_at", -1))
    return render_template("targets.html", username=username, targets=targets_list, form_state=target_form_state({"approved_users": [username]}))

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

    target = collection_targets.find_one({"_id": exp["target_id"]})
    target_name = target["name"] if target else "unknown target"
    recent_experiments = get_recent_experiments(username, limit=8)
    exp = prepare_experiment_for_view(exp)

    return render_template(
        "experimentdetails.html",
        exp=exp,
        target=target or {},
        target_name=target_name,
        username=username,
        recent_experiments=recent_experiments
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



#profile
@app.route('/profile')
def profile():
    """Render the logged-in user's profile view."""
    res = ensure_user_logged_in()

    if res is None:
        user = {
            #"username": session["user"],
            "username": session["username"],
            "email": session["email"]
        }
        res = render_template('profile.html', user=user)

    return res

#logout

@app.route('/logout')
def logout():
    """Clear session and return user to login screen."""
    #session.pop("user", None)
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('user_login'))


if __name__ == '__main__':
    app.run(debug=True)

