# server/Security_scans/broken_authentication_scan.py

import requests
from bs4 import BeautifulSoup

def check_broken_authentication(url):
    """
    Performs a basic broken authentication scan by detecting a login form on the target website
    and evaluating several security-related attributes.
    
    Methodology:
      - If the URL does not contain the word "login", append "/login" to try to fetch a login page.
      - Look for a <form> that contains an <input type="password">.
      - If no login form is found, assume no broken authentication issues (score 10/10).
      - If a login form is found, evaluate:
          * Form method: POST adds 2 points; non-POST subtracts 2.
          * Presence of a hidden CSRF token field (name contains "csrf"): adds 2 points.
          * Presence of a CAPTCHA (any element with "captcha" in its id or class): adds 1 point.
          * Password field autocomplete: if set to "off", adds 1 point; if not, subtracts 1 point.
      - Start with a base score of 5 if a login form is detected, adjust per above, and then clamp the score between 1 and 10.
    
    Returns:
      A string of the form:
      "Broken Authentication Scan score: X/10 (details...)"
    """
    try:
        # If the URL doesn't have "login" in it, try appending "/login"
        if "login" not in url.lower():
            test_url = url.rstrip("/") + "/login"
        else:
            test_url = url

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
            # No login form found. We assume there is no opportunity for broken authentication issues.
            return "Broken Authentication Scan score: 10/10 (No login form detected)"
        
        # Base score if a login form is found
        score = 5
        details = []
        
        # Evaluate form method
        form_method = login_form.get("method", "").lower()
        if form_method == "post":
            score += 2
            details.append("Form method is POST")
        else:
            score -= 2
            details.append(f"Form method is not POST (found: '{form_method or 'GET'}')")
        
        # Check for CSRF token: look for a hidden input whose name includes "csrf"
        csrf_token_found = any("csrf" in (inp.get("name") or "").lower() 
                               for inp in login_form.find_all("input", {"type": "hidden"}))
        if csrf_token_found:
            score += 2
            details.append("CSRF token present")
        else:
            details.append("No CSRF token found")
        
        # Check for CAPTCHA: search for any element (in the form or the entire page) with 'captcha' in its id or class
        captcha_found = (
            login_form.find(attrs={"id": lambda x: x and "captcha" in x.lower()}) or
            login_form.find(attrs={"class": lambda x: x and "captcha" in x.lower()}) or
            soup.find(attrs={"id": lambda x: x and "captcha" in x.lower()}) or
            soup.find(attrs={"class": lambda x: x and "captcha" in x.lower()})
        )
        if captcha_found:
            score += 1
            details.append("CAPTCHA detected")
        else:
            details.append("No CAPTCHA detected")
        
        # Check password field's autocomplete attribute
        password_input = login_form.find("input", {"type": "password"})
        autocomplete_value = (password_input.get("autocomplete") or "").lower()
        if autocomplete_value == "off":
            score += 1
            details.append("Password autocomplete set to off")
        else:
            score -= 1
            details.append("Password autocomplete not set to off")
        
        # Clamp the final score between 1 and 10
        if score < 1:
            score = 1
        elif score > 10:
            score = 10

        return f"Broken Authentication Scan score: {score}/10 ({'; '.join(details)})"
    
    except Exception as e:
        return f"Error performing broken authentication scan: {str(e)}"


