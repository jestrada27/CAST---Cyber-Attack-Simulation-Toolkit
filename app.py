from flask import Flask, request, session, redirect, render_template, flash, url_for
from pymongo import MongoClient
import os
import bcrypt
from dotenv import load_dotenv
import math  # ADDED

load_dotenv()

connection = os.getenv('MONGODB_URI')

dbclient = MongoClient(connection, tlsAllowInvalidCertificates=True)

database_name = dbclient["CAST"]
collection_users = database_name["users"]

# added collections
collection_dns = database_name["dns_logs"]
collection_bruteforce = database_name["bruteforce_telemetry"]

app = Flask(__name__)
app.secret_key = os.getenv('SECRETKEY')


#create account

@app.route('/createaccount', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_pw = request.form['confirm_pw']

        if password != confirm_pw:
            flash('Password not the same', 'danger')
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


#user login-

@app.route('/', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = collection_users.find_one({"username": username})

        if user:
            database_user = user['username']
            database_pw = user['password']
            if bcrypt.checkpw(password.encode('utf-8'), database_pw):
                session["user"] = database_user
                flash('Logged in', 'success')
                return redirect('/main_dashboard')
            else:
                flash('Incorrect login info', 'danger')
        else:
            flash('Incorrect login info', 'danger')

    return render_template('login.html')



# main-dashboard


@app.route('/main_dashboard')
def main_dashboard():

    if "user" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for('user_login'))

    username = session["user"]

    # ADDED: Fetch recent brute force and DNS logs
    recent_bruteforce = list(collection_bruteforce.find().sort("_id", -1).limit(5))
    recent_dns = list(collection_dns.find().sort("_id", -1).limit(5))

    return render_template(
        'maindashboard.html',
        username=username,
        recent_bruteforce=recent_bruteforce,
        recent_dns=recent_dns
    )



# DNS TUNNELING


def calculate_entropy(text):
    if not text:
        return 0

    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1

    entropy = 0
    length = len(text)

    for c in freq:
        p = freq[c] / length
        entropy += -p * math.log2(p)

    return entropy


@app.route('/dns_test', methods=['GET', 'POST'])
def dns_test():

    if "user" not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for('user_login'))

    if request.method == 'POST':
        domain = request.form['domain']

        threshold_frequency = 5
        threshold_entropy = 3.5

        count = collection_dns.count_documents({"domain": domain})

        subdomain = domain.split(".")[0]
        entropy_value = calculate_entropy(subdomain)

        flag = "normal"

        if count >= threshold_frequency:
            flag = "high_frequency"

        if entropy_value >= threshold_entropy:
            flag = "high_entropy"

        result = {
            "domain": domain,
            "entropy": round(entropy_value, 2),
            "count": count + 1,
            "flag": flag
        }

        collection_dns.insert_one(result)

        return render_template("dns_result.html", result=result)

    return render_template("dns_test.html")



# logout

@app.route('/logout')
def logout():
    session.pop("user", None)
    flash("You have been logged out.", "success")
    return redirect(url_for('user_login'))


if __name__ == '__main__':
    app.run(debug=True)