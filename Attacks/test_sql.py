# test_sqli.py - Test file for the SQL Injection attack route
# Run while app.py is running, update username and password before running

import requests

# Base URL pointing to the running Flask app
BASE_URL = "http://localhost:5000"

# Session object so the login cookie carries over to all requests
session = requests.Session()

# Login to get a valid session cookie
login = session.post(BASE_URL + "/", data={
    "username": "your_username",
    "password": "your_password"
})
print("Login Status Code:", login.status_code)

# SQL injection test payloads - mix of attack patterns and normal input
sqli_payloads = [
    # Auth bypass
    "' OR '1'='1",

    # OR 1=1 variation
    "' OR 1=1 -- ",

    # Drop table attack
    "'; DROP TABLE users; --",

    # Union based injection
    "' UNION SELECT NULL --",

    # Comment bypass
    "admin' --",

    # Double quote variation
    "\" OR \"1\"=\"1",

    # Insert injection attempt
    "'; INSERT INTO users VALUES ('hacker','hacker'); --",

    # Normal input - should NOT trigger
    "hello world"
]

# Run each payload through the sqli_start route and print the result
for payload in sqli_payloads:
    print(f"\nTesting payload: {payload}")

    sqli_test = session.post(BASE_URL + "/sqli_start", json={
        # Replace with a real target_id from your MongoDB targets collection
        "target_id": "000000000000000000000001",
        "payload": payload
    })

    print("Status Code:", sqli_test.status_code)

    # Parse and print the response
    try:
        result = sqli_test.json()
        print("Vulnerability Detected:", result.get("vulnerability"))
        print("Log:")
        for log_entry in result.get("sqli_log", []):
            print("  -", log_entry)
    except Exception as e:
        print("Could not parse response:", e)
        print("Raw response:", sqli_test.text)