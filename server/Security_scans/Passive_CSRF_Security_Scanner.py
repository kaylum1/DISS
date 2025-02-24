import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Headers and cookie flags important for CSRF protection
REQUIRED_HEADERS = ["Origin", "Referer", "X-Frame-Options"]
SECURE_COOKIE_FLAGS = ["Secure", "HttpOnly", "SameSite"]

# Score deductions for misconfigurations
SCORE_DEDUCTIONS = {
    "missing_csrf_token": 4,  # Forms without CSRF tokens
    "missing_headers": 3,     # Missing Referer, Origin, or X-Frame-Options
    "weak_cookies": 2,        # Cookies missing Secure and SameSite
    "open_cors": 3,           # CORS allows unauthorized cross-site requests
}

def get_page_content(url):
    """
    Fetches the HTML content of a webpage.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text, response.headers, response.cookies
    except requests.RequestException as e:
        print(f"[Error] Could not retrieve page content for {url}: {e}")
        return None, None, None

def detect_csrf_tokens(html):
    """
    Identifies forms on the page and checks if they contain CSRF protection tokens.
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")

    unprotected_forms = []
    for form in forms:
        if not form.find("input", {"name": "csrf_token"}) and not form.find("input", {"name": "_csrf"}):
            unprotected_forms.append(form)

    return unprotected_forms

def detect_security_headers(headers):
    """
    Checks for essential security headers that mitigate CSRF.
    """
    missing_headers = []
    for header in REQUIRED_HEADERS:
        if header not in headers:
            missing_headers.append(header)
    return missing_headers

def analyze_cookies(cookies):
    """
    Checks cookies for security flags (SameSite, Secure, HttpOnly).
    """
    weak_cookies = []
    for cookie in cookies:
        if not all(flag in cookie._rest.keys() for flag in SECURE_COOKIE_FLAGS):
            weak_cookies.append(cookie.name)
    return weak_cookies

def detect_open_cors(headers):
    """
    Checks if CORS policy is too permissive.
    """
    cors_policy = headers.get("Access-Control-Allow-Origin", "")
    if cors_policy == "*":
        return True
    return False

def analyze_csrf_security(url):
    """
    Performs CSRF security risk analysis and assigns a security score.
    """
    base_score = 10
    details = []

    # Fetch HTML, headers, and cookies
    html, headers, cookies = get_page_content(url)
    if not html or not headers or cookies is None:
        return 1, ["❌ Could not analyze the webpage."]

    # CSRF Token Analysis
    unprotected_forms = detect_csrf_tokens(html)
    if unprotected_forms:
        base_score -= SCORE_DEDUCTIONS["missing_csrf_token"]
        details.append(f"❌ {len(unprotected_forms)} forms without CSRF protection (Score -{SCORE_DEDUCTIONS['missing_csrf_token']})")

    # Security Header Analysis
    missing_headers = detect_security_headers(headers)
    if missing_headers:
        base_score -= SCORE_DEDUCTIONS["missing_headers"]
        details.append(f"⚠️ Missing security headers: {', '.join(missing_headers)} (Score -{SCORE_DEDUCTIONS['missing_headers']})")

    # Cookie Security Analysis
    weak_cookies = analyze_cookies(cookies)
    if weak_cookies:
        base_score -= SCORE_DEDUCTIONS["weak_cookies"]
        details.append(f"⚠️ Cookies without security flags: {', '.join(weak_cookies)} (Score -{SCORE_DEDUCTIONS['weak_cookies']})")

    # Open CORS Policy Analysis
    if detect_open_cors(headers):
        base_score -= SCORE_DEDUCTIONS["open_cors"]
        details.append(f"⚠️ CORS policy is too permissive (Score -{SCORE_DEDUCTIONS['open_cors']})")

    # Ensure score stays within 1-10 range
    final_score = max(1, min(10, base_score))

    if final_score == 10:
        details.append("✅ No significant CSRF risks detected.")
    elif final_score < 5:
        details.append("⚠️ High risk: The website has serious CSRF vulnerabilities!")
    else:
        details.append("⚠️ Moderate risk: Some CSRF security improvements are needed.")

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
    import argparse
    parser = argparse.ArgumentParser(description="Passive CSRF Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    base_url = get_base_url(args.url)
    print(f"🔍 Scanning CSRF security for: {base_url}\n")

    score, details = analyze_csrf_security(base_url)

    print("\n--- 🔍 CSRF Security Report ---")
    for line in details:
        print(f" - {line}")

    print("\n--- 🔢 Security Score ---")
    print(f"Security Score: {score} / 10")
    if score < 5:
        print("⚠️ The website has serious CSRF vulnerabilities!")
    elif score < 8:
        print("⚠️ The website has some CSRF security risks. Fixing recommended.")
    else:
        print("✅ The website appears to be well-protected against CSRF.")

if __name__ == "__main__":
    main()
