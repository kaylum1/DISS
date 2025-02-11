# server/Privacy_scan/cookie_privacy_scan.py

import requests

def check_cookie_privacy(url):
    """
    Evaluates cookie privacy by checking for Secure and HttpOnly flags on cookies.
    
    Method:
      - Fetch the URL.
      - For each cookie in the response, check if it has both Secure and HttpOnly attributes.
    
    Scoring:
      - If no cookies are set: score is 10.
      - Otherwise, score = (number of cookies with both flags / total cookies) * 10 (minimum 1).
    
    Returns:
      A string with the final score and details.
    """
    try:
        response = requests.get(url, timeout=10)
        cookies = response.cookies
        total = len(cookies)
        if total == 0:
            return "Cookie Privacy Scan score: 10/10 (No cookies set)"
        
        good = 0
        details_list = []
        for cookie in cookies:
            flags = []
            if cookie.secure:
                flags.append("Secure")
            # Check for HttpOnly flag in the cookie's internal _rest dictionary.
            if "httponly" in cookie._rest.keys():
                flags.append("HttpOnly")
            if len(flags) == 2:
                good += 1
            details_list.append(f"{cookie.name}: {', '.join(flags) if flags else 'Missing flags'}")
        
        score = int((good / total) * 10)
        if score < 1:
            score = 1
        details = f"{good}/{total} cookies have Secure and HttpOnly. Details: " + "; ".join(details_list)
        return f"Cookie Privacy Scan score: {score}/10 ({details})"
    except Exception as e:
        return f"Error in Cookie Privacy Scan: {str(e)}"

# For testing:
#if __name__ == "__main__":
#    test_url = "https://www.example.com/"
#    print(check_cookie_privacy(test_url))
