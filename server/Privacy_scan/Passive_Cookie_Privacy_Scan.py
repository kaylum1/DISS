import requests

def analyze_cookie_privacy(url):
    """
    Passively scans the cookies set by a website and evaluates their privacy.

    It checks each cookie for:
      - Secure flag: Ensures the cookie is only sent over HTTPS.
      - HttpOnly flag: Prevents the cookie from being accessed via JavaScript.
      
    A base score of 10 is reduced by deduction points for each cookie missing a flag:
      - Missing Secure flag: deduct 2 points.
      - Missing HttpOnly flag: deduct 2 points.
    
    If no cookies are set, the scan returns a score of 10.
    
    Returns:
      (final_score, details)
      
      - final_score: An integer between 1 and 10 (10 means all cookies have proper privacy settings).
      - details: A list of strings describing the findings for each cookie.
    """
    try:
        response = requests.get(url, timeout=10)
    except Exception as e:
        return 1, [f"Error fetching page: {e}"]
    
    details = []
    deduction = 0

    cookies = response.cookies
    if not cookies:
        details.append("No cookies were set by the site.")
        return 10, details  # No cookies means no cookie-related privacy risk.
    
    for cookie in cookies:
        name = cookie.name
        secure_flag = cookie.secure
        # The HttpOnly flag is typically stored in the cookie's "rest" dictionary.
        http_only_flag = cookie._rest.get("HttpOnly")
        details.append(f"Cookie '{name}': Secure={secure_flag}, HttpOnly={http_only_flag}")
        
        if not secure_flag:
            deduction += 2
            details.append(f"  - Cookie '{name}' is missing the Secure flag (deduction 2).")
        if not http_only_flag:
            deduction += 2
            details.append(f"  - Cookie '{name}' is missing the HttpOnly flag (deduction 2).")
    
    final_score = max(1, min(10, 10 - deduction))
    if final_score == 10:
        details.append("✅ All cookies have proper privacy flags.")
    elif final_score < 5:
        details.append("⚠️ High risk: Many cookies are missing important security flags!")
    else:
        details.append("⚠️ Moderate risk: Some cookies are missing security flags.")
    
    return final_score, details

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Passive Cookie Privacy Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()
    score, details = analyze_cookie_privacy(args.url)
    print(f"Final Score: {score}/10")
    for line in details:
        print(line)
