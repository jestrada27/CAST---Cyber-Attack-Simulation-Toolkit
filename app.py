from flask import Flask, request, session, redirect, render_template, flash, url_for
from pymongo import MongoClient
import os
import bcrypt
from dotenv import load_dotenv
load_dotenv()

connection = os.getenv('MONGODB_URI')

dbclient = MongoClient(connection, tlsAllowInvalidCertificates=True)  

database_name = dbclient["CAST"]
collection_users = database_name["users"]

app = Flask(__name__)
app.secret_key = os.getenv('SECRETKEY')

#createaccount

@app.route('/createaccount', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_pw = request.form['confirm_pw']

        if password != confirm_pw:
            flash('Password not the same', 'danger' )
            return redirect('/createaccount')
        
        if collection_users.find_one({"username": username}):
            flash('User already exists', 'danger')
            return redirect('/createaccount')

        if collection_users.find_one({"email": email}):
            flash('Email already used', 'danger')
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

#userlogin
    
@app.route('/', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        #user = collection_users.find_one({"username": username, "password": password})
        user = collection_users.find_one({"username": username})

        if user:
            database_user = user['username']
            database_pw = user['password']
            if bcrypt.checkpw(password.encode('utf-8'), database_pw):
                session["user"] = database_user
                flash('Logged in', 'success')
                return redirect('/main_dashboard')
            else:
                flash('Incorrect password', 'danger')
        else:
            flash('Incorrect username', 'danger')
    
    return render_template('login.html')

#maindashboard

@app.route('/main_dashboard')
def main_dashboard():

    if "user" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for('user_login'))

    username = session["user"]
    return render_template('maindashboard.html', username=username)

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
    
