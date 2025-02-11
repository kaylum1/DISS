# server/Security_scans/security_headers_checker.py

import requests

def check_security_headers(url):
    """
    Performs a security header scan on the given URL and returns a security score between 1 and 10.

    The scan checks for the presence of key security headers and assigns points as follows:
      - Strict-Transport-Security: 2 points
      - Content-Security-Policy: 2 points
      - X-Content-Type-Options: 2 points
      - X-Frame-Options: 1.5 points
      - Referrer-Policy: 1 point
      - Permissions-Policy (or Feature-Policy): 1.5 points

    The total raw score is then rounded to the nearest integer (minimum of 1).

    Returns:
        A string with the final score and details about which headers were found.
    """
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        score = 0.0
        details = []

        # Strict-Transport-Security (HSTS)
        if 'Strict-Transport-Security' in headers:
            score += 2
            details.append("HSTS present")
        else:
            details.append("HSTS missing")

        # Content-Security-Policy (CSP)
        if 'Content-Security-Policy' in headers:
            score += 2
            details.append("CSP present")
        else:
            details.append("CSP missing")

        # X-Content-Type-Options
        if 'X-Content-Type-Options' in headers:
            score += 2
            details.append("X-Content-Type-Options present")
        else:
            details.append("X-Content-Type-Options missing")

        # X-Frame-Options
        if 'X-Frame-Options' in headers:
            score += 1.5
            details.append("X-Frame-Options present")
        else:
            details.append("X-Frame-Options missing")

        # Referrer-Policy
        if 'Referrer-Policy' in headers:
            score += 1
            details.append("Referrer-Policy present")
        else:
            details.append("Referrer-Policy missing")

        # Permissions-Policy or Feature-Policy
        if 'Permissions-Policy' in headers:
            score += 1.5
            details.append("Permissions-Policy present")
        elif 'Feature-Policy' in headers:
            score += 1.5
            details.append("Feature-Policy present")
        else:
            details.append("Permissions/Feature-Policy missing")

        # Calculate final score (round to nearest integer; minimum 1)
        final_score = round(score)
        if final_score < 1:
            final_score = 1

        details_str = "; ".join(details)
        return f"Security Headers score: {final_score}/10 ({details_str})"

    except Exception as e:
        return f"Error performing security headers scan: {str(e)}"


