from flask import Flask, request, session, redirect, render_template, flash, url_for
from pymongo import MongoClient
import os
import bcrypt
from dotenv import load_dotenv
import time

load_dotenv()

connection = os.getenv('MONGODB_URI')

dbclient = MongoClient(connection, tlsAllowInvalidCertificates=True)  

database_name = dbclient["CAST"]
collection_users = database_name["users"]

app = Flask(__name__)
app.secret_key = os.getenv('SECRETKEY')


#password checking for if the password is a certain length and complexity
def good_password_check(password):
    #len greater than 7 and less than 40, 1 lowercase, 1 uppercase, 1 number, and 1 special character ~`! @#$%^&*()_-+={[}]|\:;\"'<,>.?/ allowed 
    lowercase = False
    uppercase = False
    number = False
    special_char = False
    special_char_list = "~`! @#$%^&*()_-+={[}]|\:;\"'<,>.?/"
    
    if len(password) < 7 or len(password) > 40:
        return 'Password needs to be 7-40 characters in length.'
        #flash('Password needs to be 7-40 characters in length.', 'danger')
        #return redirect('/createaccount')
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

#createaccount

@app.route('/createaccount', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_pw = request.form['confirm_pw']

        #username checking for a certain length
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
    data = request.get_json()
    entered = data["password"]

    user = collection_users.find_one(
        {"username": session["user"]}
    )

    if bcrypt.checkpw(entered.encode('utf-8'), user['password']):
        return {"valid": True}

    return {"valid": False}

@app.post("/change-password")
def change_password():
    data = request.get_json()
    new_pass = data["new_password"]

    #new password check for security improvement and for password rules - Noah
    bad_password = good_password_check(new_pass)
    if bad_password:
            return {"success": False, "message": bad_password}, 400


    # Hash password
    hashed_pass = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt())

    # Update MongoDB
    result = collection_users.update_one(
        {"username": session["user"]},
        {"$set": {"password": hashed_pass}}
    )

    return {"success": result.modified_count == 1}

@app.post("/api/change-username")
def change_username():
    if "user" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    data = request.get_json() or {}
    new_username = (data.get("username") or "").strip()

    #Check new username for username rules - Noah
    if len(new_username) < 5 or len(new_username) > 30:
        return {"success": False, "message": "Username needs to be 5 to 30 characters long"}


    if not new_username:
        return {"success": False, "message": "Username is required."}, 400

    #Make sure the username actaully changed from previous
    if new_username == session["user"]:
        return {"success": False, "message": "No change detected"}, 400

    # Make sure that the new username isnt already in use
    duplicate_check = collection_users.find_one({"email": new_username})

    if duplicate_check:
        return {"success": False, "message": "Username already in use"}, 400

    # Update MongoDB
    result = collection_users.update_one(
        {"username": session["user"]},
        {"$set": {"username": new_username}}
    )

    if result.modified_count > 0:
        #update the local session
        session["user"] = new_username

    return {"success": result.modified_count == 1}

@app.post("/api/change-email")
def change_email():
    if "user" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    data = request.get_json() or {}
    new_email = (data.get("email") or "").strip()

    if not new_email:
        return {"success": False, "message": "Email is required."}, 400

    # Make sure the username actaully changed from previous
    if new_email == session["user"]:
        return {"success": False, "message": "No change detected"}, 400

    # Make sure that the new username isnt already in use
    duplicate_check = collection_users.find_one({"email": new_email})

    if duplicate_check:
        return {"success": False, "message": "Email already in use"}, 400

    # Update MongoDB
    result = collection_users.update_one(
        {"username": session["user"]},
        {"$set": {"email": new_email}}
    )

    if result:
        #update the local session
        session["email"] = new_email

    return {"success": result.modified_count == 1}

@app.post("/delete-account")
def delete_account():
    if "user" not in session:
        return {"success": False, "message": "Not logged in"}, 401

    username = session["user"]

    result = collection_users.delete_one({"username": username})

    # Clear session
    session.clear()

    if result.deleted_count == 1:
        return {"success": True}
    else:
        return {"success": False, "message": "User not found."}, 404



#userlogin

#limiting number of login attempts 
attempts_num = 6

@app.route('/', methods=['GET', 'POST'])
def user_login():

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
        password = request.form['password'].strip()

        #user = collection_users.find_one({"username": username, "password": password})
        user = collection_users.find_one({"username": username})

        if user:
            database_user = user['username']
            database_pw = user['password']
            if bcrypt.checkpw(password.encode('utf-8'), database_pw):
                session["user"] = database_user
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
    if "user" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for('user_login'))
    return None

#maindashboard

@app.route('/main_dashboard')
def main_dashboard():

    if "user" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for('user_login'))

    username = session["user"]
    return render_template('maindashboard.html', username=username)

#profile
@app.route('/profile')
def profile():
    res = ensure_user_logged_in()

    if res is None:
        user = {
            "username": session["user"],
            "email": session["email"]
        }
        res = render_template('profile.html', user=user)

    return res

#logout

@app.route('/logout')
def logout():
    session.pop("user", None)
    flash("You have been logged out.", "success")
    return redirect(url_for('user_login'))


if __name__ == '__main__':
    app.run(debug=True)

# username = input("Enter user: ")
# password = input("Enter password: ")
# user = collection_users.find_one({"username": username, "password": password})

# print("Correct")

# @app.route('/main_dashboard')
# def main_dashboard():
    
