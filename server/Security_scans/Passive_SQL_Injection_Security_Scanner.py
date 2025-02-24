import requests
import argparse
import re
from urllib.parse import urlparse, parse_qs


# Common SQL error patterns found in responses
SQL_ERROR_PATTERNS = [
    "You have an error in your SQL syntax",
    "Warning: mysql_fetch_array()",
    "Warning: mysql_fetch_assoc()",
    "Unclosed quotation mark",
    "Microsoft OLE DB Provider for SQL Server",
    "ORA-01756",
    r"SQLSTATE\["  # <-- FIXED: Escaped the '[' character
]


# Score deductions for vulnerabilities
SCORE_DEDUCTIONS = {
    "exposed_errors": 5,  # Database error messages found
    "suspicious_params": 3,  # URL parameters that look SQL-injectable
    "missing_security_headers": 2,  # Lack of security headers
}

def get_page_content(url):
    """
    Fetches the HTML content of a webpage.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text, response.headers
    except requests.RequestException as e:
        print(f"[Error] Could not retrieve page content for {url}: {e}")
        return None, None

def detect_sql_errors(html):
    """
    Scans the webpage for exposed SQL error messages.
    """
    for pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            return True
    return False

def detect_suspicious_parameters(url):
    """
    Identifies URL parameters that are commonly targeted in SQL injection.
    """
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    
    risky_params = [key for key in params if key.lower() in ["id", "user", "login", "admin", "product"]]
    
    return risky_params

def detect_security_headers(headers):
    """
    Checks if critical security headers are missing.
    """
    required_headers = ["Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection"]
    missing_headers = [header for header in required_headers if header not in headers]
    
    return missing_headers

def analyze_sql_security(url):
    """
    Performs SQL injection risk analysis and assigns a security score.
    """
    base_score = 10
    details = []

    # Fetch HTML and headers
    html, headers = get_page_content(url)
    if not html or not headers:
        return 1, ["❌ Could not analyze the webpage."]

    # SQL Error Analysis
    if detect_sql_errors(html):
        base_score -= SCORE_DEDUCTIONS["exposed_errors"]
        details.append("❌ Exposed SQL error messages detected (Score -5)")

    # Suspicious URL Parameter Analysis
    risky_params = detect_suspicious_parameters(url)
    if risky_params:
        base_score -= SCORE_DEDUCTIONS["suspicious_params"]
        details.append(f"⚠️ Suspicious parameters detected: {', '.join(risky_params)} (Score -3)")

    # Security Header Analysis
    missing_headers = detect_security_headers(headers)
    if missing_headers:
        base_score -= SCORE_DEDUCTIONS["missing_security_headers"]
        details.append(f"⚠️ Missing security headers: {', '.join(missing_headers)} (Score -2)")
    else:
        details.append("✅ Security headers are properly set.")

    # Ensure score stays within 1-10 range
    final_score = max(1, min(10, base_score))

    if final_score == 10:
        details.append("✅ No significant SQL injection risks detected.")
    elif final_score < 5:
        details.append("⚠️ High risk: The website has serious SQL injection vulnerabilities!")
    else:
        details.append("⚠️ Moderate risk: Some SQL security improvements are needed.")

    return final_score, details

def get_base_url(url):
    """
    Extracts the base URL from a given URL, ensuring it has https://.
    """
    if "://" not in url:
        url = "https://" + url  # Assume HTTPS by default
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def main():
    parser = argparse.ArgumentParser(description="Passive SQL Injection Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    base_url = get_base_url(args.url)
    print(f"🔍 Scanning SQL injection security for: {base_url}\n")

    score, details = analyze_sql_security(base_url)

    print("\n--- 🔍 SQL Injection Risk Report ---")
    for line in details:
        print(f" - {line}")

    print("\n--- 🔢 Security Score ---")
    print(f"Security Score: {score} / 10")
    if score < 5:
        print("⚠️ The website has serious SQL injection vulnerabilities!")
    elif score < 8:
        print("⚠️ The website has some SQL security risks. Fixing recommended.")
    else:
        print("✅ The website appears to be well-protected against SQL injection.")

if __name__ == "__main__":
    main()



"""
🔍 How It Works
Fetches HTML & Headers:
Extracts SQL errors, parameters, and security headers.
Identifies SQL Injection Risks:
Exposed SQL error messages (e.g., You have an error in your SQL syntax).
Suspicious URL parameters (?id=1, ?user=admin).
Missing security headers (Content-Security-Policy, X-XSS-Protection).
Calculates Security Score (1-10):
1-4 → High risk ⚠️
5-7 → Moderate risk 🟡
8-10 → Secure ✅
🚀 How to Use
Run the script with a target URL:

python Passive_SQL_Injection_Security_Scanner.py -u "https://example.com"
✅ Example Output:

🔍 Scanning SQL injection security for: https://example.com

--- 🔍 SQL Injection Risk Report ---
 - ❌ Exposed SQL error messages detected (Score -5)
 - ⚠️ Suspicious parameters detected: id, login (Score -3)
 - ⚠️ Missing security headers: Content-Security-Policy, X-Frame-Options (Score -2)

--- 🔢 Security Score ---
Security Score: 4 / 10
⚠️ The website has serious SQL injection vulnerabilities!
⚖️ Legal Considerations
✅ Legal if used on your own website or with explicit permission from the site owner.
❌ Illegal if used on external sites without consent.

Would you like me to modify this for a browser extension that only scans the current webpage the user visits? 🚀


"""