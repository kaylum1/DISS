# server/Security_scans/scanner_cookie_security_check.py

import requests

def check_cookie_security(url):
    """
    Performs a cookie security check by analyzing the cookies set by the server.

    For each cookie, the following attributes are considered:
      - Secure: if True, add 3 points.
      - HttpOnly: if present in the cookie's internal attributes, add 3 points.
      - SameSite: if set to "strict", add 4 points; if "lax", add 2 points; else 0.
    
    Maximum score per cookie is 10.
    If no cookies are set, the function returns 10/10.
    
    The final score is computed as the average of all cookie scores (rounded to the nearest integer).

    Returns:
      A string in the format:
      "Cookie Security Check score: X/10 (Details: cookie1: score (attributes); cookie2: score (attributes); ...)"
    """
    try:
        response = requests.get(url, timeout=10)
        cookies = response.cookies

        # If no cookies are set, assume it's secure
        if not cookies or len(cookies) == 0:
            return "Cookie Security Check score: 10/10 (No cookies set)"

        cookie_scores = []
        details_list = []

        for cookie in cookies:
            score = 0
            attributes_found = []

            # Check the 'Secure' attribute
            if cookie.secure:
                score += 3
                attributes_found.append("Secure")
            else:
                attributes_found.append("Not Secure")

            # Check for HttpOnly in cookie._rest (it might be present as "HttpOnly" or "httponly")
            httponly = cookie._rest.get("HttpOnly") or cookie._rest.get("httponly")
            if httponly or "HttpOnly" in cookie._rest:
                score += 3
                attributes_found.append("HttpOnly")
            else:
                attributes_found.append("Not HttpOnly")

            # Check the SameSite attribute (if available)
            samesite = cookie._rest.get("samesite")
            if samesite:
                samesite = samesite.lower()
                if samesite == "strict":
                    score += 4
                    attributes_found.append("SameSite=Strict")
                elif samesite == "lax":
                    score += 2
                    attributes_found.append("SameSite=Lax")
                else:
                    attributes_found.append(f"SameSite={samesite}")
            else:
                attributes_found.append("No SameSite")

            # Clamp individual cookie score between 1 and 10
            if score < 1:
                score = 1
            elif score > 10:
                score = 10

            cookie_scores.append(score)
            details_list.append(f"{cookie.name}: {score} ({', '.join(attributes_found)})")

        # Calculate the average score across all cookies
        average_score = round(sum(cookie_scores) / len(cookie_scores))
        details_str = "; ".join(details_list)
        return f"Cookie Security Check score: {average_score}/10 (Details: {details_str})"
    
    except Exception as e:
        return f"Error performing cookie security check: {str(e)}"





