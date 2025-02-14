import requests
import argparse
from bs4 import BeautifulSoup

def check_broken_authentication(url):
    """
    Performs a basic broken authentication scan by detecting a login form on the target website
    and evaluating several security-related attributes.

    Methodology:
      - If the URL does not contain "login", try appending "/login".
      - Detect forced redirects to login pages and return 10/10 if authentication is enforced.
      - Look for a <form> with an <input type="password"> to identify login pages.
      - If a login form is found, evaluate:
          * Form method: POST adds 2 points; non-POST subtracts 2.
          * Presence of a CSRF token (input name contains "csrf"): adds 2 points.
          * Presence of a CAPTCHA (any element with "captcha" in id or class): adds 1 point.
          * Password field autocomplete: if set to "off", adds 1 point; if not, subtracts 1.
      - Score starts at 5 and is adjusted, clamped between 1 and 10.

    Returns:
      "Broken Authentication Scan score: X/10 (details...)"
    """
    try:
        print(f"\n🔍 Scanning: {url}")

        # If the URL doesn't have "login" in it, try appending "/login"
        if "login" not in url.lower():
            test_url = url.rstrip("/") + "/login"
        else:
            test_url = url

        # Fetch the webpage but prevent auto-following redirects
        response = requests.get(test_url, timeout=10, allow_redirects=False)

        # Detect forced login redirects
        if response.status_code in [301, 302] and "login.php" in response.headers.get("Location", "").lower():
            return "Broken Authentication Scan score: 10/10 (Redirected to login page, authentication required ✅)"

        # Fetch full page content if no redirect
        response = requests.get(test_url, timeout=10)
        html = response.text
        soup = BeautifulSoup(html, "html.parser")

        # Find the first form that contains a password input
        login_form = None
        for form in soup.find_all("form"):
            if form.find("input", {"type": "password"}):
                login_form = form
                break

        if not login_form:
            return "Broken Authentication Scan score: 10/10 (No login form detected ✅)"

        # Base score if a login form is found
        score = 5
        details = []

        # Evaluate form method
        form_method = login_form.get("method", "").lower()
        if form_method == "post":
            score += 2
            details.append("Form method is POST ✅")
        else:
            score -= 2
            details.append(f"Form method is not POST ❌ (found: '{form_method or 'GET'}')")

        # Check for CSRF token
        csrf_token_found = any("csrf" in (inp.get("name") or "").lower() 
                               for inp in login_form.find_all("input", {"type": "hidden"}))
        if csrf_token_found:
            score += 2
            details.append("CSRF token present ✅")
        else:
            details.append("No CSRF token found ❌")

        # Check for CAPTCHA
        captcha_found = (
            login_form.find(attrs={"id": lambda x: x and "captcha" in x.lower()}) or
            login_form.find(attrs={"class": lambda x: x and "captcha" in x.lower()}) or
            soup.find(attrs={"id": lambda x: x and "captcha" in x.lower()}) or
            soup.find(attrs={"class": lambda x: x and "captcha" in x.lower()})
        )
        if captcha_found:
            score += 1
            details.append("CAPTCHA detected ✅")
        else:
            details.append("No CAPTCHA detected ❌")

        # Check password field autocomplete
        password_input = login_form.find("input", {"type": "password"})
        autocomplete_value = (password_input.get("autocomplete") or "").lower()
        if autocomplete_value == "off":
            score += 1
            details.append("Password autocomplete set to off ✅")
        else:
            score -= 1
            details.append("Password autocomplete not set to off ❌")

        # Clamp score between 1 and 10
        score = max(1, min(score, 10))

        return f"Broken Authentication Scan score: {score}/10 ({'; '.join(details)})"

    except requests.exceptions.ConnectionError:
        return f"❌ Error: Could not connect to {url}. Is the server running?"
    except Exception as e:
        return f"❌ Error performing broken authentication scan: {str(e)}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Broken Authentication Scanner")
    parser.add_argument("url", nargs="?", default="http://localhost/DVWA/index.php", help="Target URL to scan")
    args = parser.parse_args()

    result = check_broken_authentication(args.url)
    print("\n🔎 Scan Result:", result)

'''

    python3 broken_authentication_scan_test.py http://localhost/DVWA/index.php

    Broken Authentication Scan score: 10/10 (Redirected to login page, authentication required ✅)
                                             


    python3 broken_authentication_scan_test.py http://localhost/DVWA/vulnerabilities/brute/

    Broken Authentication Scan score: 1/10 (Form method is not POST ❌; No CSRF token found ❌; No CAPTCHA detected ❌; Password autocomplete not set to off ❌)
'''