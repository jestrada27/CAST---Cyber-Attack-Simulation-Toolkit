from flask import Flask, request, session, redirect, render_template, flash, url_for
from flask_mail import Mail, Message
#from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
import os
import bcrypt
#from dotenv import load_dotenv
#from datetime import datetime, timedelta
import time
from bson import ObjectId
from itsdangerous import URLSafeTimedSerializer as Serializer
from Attacks.DNSTunnelingExperiment import run_dns_tunneling_experiment


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


def run_experiment_now(experiment):
    """Run an experiment module handler immediately when supported."""
    module_id = experiment.get("module_id")
    attempts = experiment.get("attempts", 5)
    rate_limit = experiment.get("rate_limit", 1.0)
    dry_run = bool(experiment.get("dry_run", True))

    if module_id == "dns":
        results = run_dns_tunneling_experiment(attempts=attempts, rate_limit=rate_limit, dry_run=dry_run)
        status = "Dry-Run Complete" if dry_run else "Completed"
        return True, status, results, "DNS tunneling simulation finished."

    return False, experiment.get("status", "Queued"), None, f"Module '{module_id}' runner is not available yet."

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
        "status": {"$in": ["Queued", "Running"]}
    })
    completed_experiment_count = collection_experiments.count_documents({
        "owner": username,
        "status": {"$in": ["Completed", "Finished", "Success"]}
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

    # Load targets
    targets = list(collection_targets.find({"owner": username}, {"name": 1}))

    # Module list
    modules = [
        {"id": "brute force", "name": "Brute Force (Controlled)"},
        {"id": "xss", "name": "XSS (Safe Test)"},
        {"id": "sqli", "name": "SQL Injection (Safe Probe)"},
        {"id": "replay", "name": "Replay (Simulated)"},
        {"id": "dns", "name": "DNS Tunneling (Lab Simulation)"},
    ]

    selected_target_id = request.args.get("target_id", "")
    selected_module_id = request.args.get("module_id", "")
    selected_attempts = request.args.get("attempts", "5")
    selected_rate_limit = request.args.get("rate_limit", "1.0")
    selected_dry_run = request.args.get("dry_run", "true").lower() in ("true", "1", "on", "yes")

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
                selected_dry_run=dry_run
            )

        if attempts < 1 or attempts > 50 or rate_limit < 0.1 or rate_limit > 10:
            flash("Use attempts 1-50 and rate_limit 0.1-10.", "danger")
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
                selected_dry_run=dry_run
            )

        if not target_id or not module_id:
            flash("Please select a target and a module.", "danger")
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
                selected_dry_run=dry_run
            )

        try:
            target_object_id = ObjectId(target_id)
        except Exception:
            flash("Selected target is invalid.", "danger")
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
                selected_dry_run=dry_run
            )

        target_exists = collection_targets.find_one({"_id": target_object_id, "owner": username}, {"_id": 1})
        if not target_exists:
            flash("Selected target was not found for your account.", "danger")
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
                selected_dry_run=dry_run
            )

        exp_doc = {
            "owner": username,
            "target_id": target_object_id,
            "module_id": module_id,
            "attempts": attempts,
            "rate_limit": rate_limit,
            "dry_run": dry_run,
            "status": "Queued",
            "created_at": datetime.utcnow()
        }

        inserted = collection_experiments.insert_one(exp_doc)
        inserted_id = inserted.inserted_id

        # DNS module runs as a safe simulation immediately after creation.
        if module_id == "dns":
            created_exp = collection_experiments.find_one({"_id": inserted_id, "owner": username})
            if created_exp:
                ok, new_status, results, run_msg = run_experiment_now(created_exp)
                if ok:
                    collection_experiments.update_one(
                        {"_id": inserted_id, "owner": username},
                        {"$set": {"status": new_status, "results": results, "started_at": results["started_at"], "completed_at": results["completed_at"]}},
                    )
                    flash(run_msg, "success")
                else:
                    flash(run_msg, "warning")
            else:
                flash("Experiment created, but execution context was not found.", "warning")
        else:
            flash("Experiment created!", "success")
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
        selected_dry_run=selected_dry_run
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

        if not name or not ip_or_url:
            flash("name and ip_or_url are required.", "danger")
            return redirect(url_for("targets"))

        # per-user uniqueness (same owner can't create same name twice)
        if collection_targets.find_one({"owner": username, "name": name}):
            flash("target name already exists for your account.", "danger")
            return redirect(url_for("targets"))

        collection_targets.insert_one({
            "owner": username,
            "name": name,
            "ip_or_url": ip_or_url,
            "consent_status": "pending",
            "created_at": datetime.utcnow()
        })

        flash("target added!", "success")
        return redirect(url_for("targets"))

    targets_list = list(collection_targets.find({"owner": username}).sort("created_at", -1))
    return render_template("targets.html", username=username, targets=targets_list)

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

    target = collection_targets.find_one({"_id": exp["target_id"]}, {"name": 1})
    target_name = target["name"] if target else "unknown target"
    recent_experiments = get_recent_experiments(username, limit=8)

    return render_template(
        "experimentdetails.html",
        exp=exp,
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

    collection_experiments.update_one(
        {"_id": experiment_object_id, "owner": username},
        {"$set": {"status": "Running", "started_at": datetime.utcnow()}},
    )

    ok, new_status, results, run_msg = run_experiment_now(exp)
    if ok:
        update_doc = {"status": new_status, "results": results, "completed_at": datetime.utcnow()}
        collection_experiments.update_one(
            {"_id": experiment_object_id, "owner": username},
            {"$set": update_doc},
        )
        flash(run_msg, "success")
    else:
        collection_experiments.update_one(
            {"_id": experiment_object_id, "owner": username},
            {"$set": {"status": "Queued"}},
        )
        flash(run_msg, "warning")

    return redirect(url_for("experimentdetails", experiment_id=experiment_id))



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

