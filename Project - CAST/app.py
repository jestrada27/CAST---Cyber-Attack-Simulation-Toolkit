from flask import Flask, request, session, redirect, render_template, flash
from pymongo import MongoClient


connection = "mongodb+srv://mail2noahf_db_user:3JilQ5uHptENec3a@castcluster.j40rgtw.mongodb.net/?appName=CASTCluster"

dbclient = MongoClient(connection, tlsAllowInvalidCertificates=True)  

database_name = dbclient["CAST"]
collection_users = database_name["users"]

app = Flask(__name__)


@app.route('/createaccount', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_pw = request.form['confirm_pw']

        if password != confirm_pw:
            flash("Password Error")
            return redirect('/createaccount')
        
        if collection_users.find_one({"username": username}):
            flash("User already exists")
            return redirect('/createaccount')

        if collection_users.find_one({"email": email}):
            flash("Email already used")
            return redirect('/createaccount')

        collection_users.insert_one({
            "username": username,
            "email": email,
            "password": password
        })

        return redirect('/')
    
    return render_template('createaccount.html')


    
@app.route('/', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = collection_users.find_one({"username": username, "password": password})

        if user:
            session["user"] = username
            return redirect('/main_dashboard')
        else:
            flash("Incorrect username or password")
    
    return render_template('login.html')
        

# username = input("Enter user: ")
# password = input("Enter password: ")
# user = collection_name.find_one({"username": username, "password": password})

# print("Correct")

# @app.route('/main_dashboard')
# def main_dashboard():
    