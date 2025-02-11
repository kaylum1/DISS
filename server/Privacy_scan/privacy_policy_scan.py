# server/Privacy_scan/privacy_policy_scan.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def check_privacy_policy(url):
    """
    Checks if the website has a Privacy Policy.
    
    Method:
      - Fetch the homepage HTML.
      - Parse the HTML for anchor tags whose text or href include "privacy policy".
      - If not found, try accessing a common URL (e.g. /privacy).
    
    Scoring:
      - If a privacy policy is detected: 10/10.
      - If not detected: 1/10.
      
    Returns:
      A string with the score and details.
    """
    try:
        response = requests.get(url, timeout=10)
        html = response.text.lower()
        soup = BeautifulSoup(html, "html.parser")
        found = False

        # Look for anchor tags that reference a privacy policy.
        for link in soup.find_all("a"):
            text = link.get_text().strip().lower()
            href = link.get("href", "").lower()
            if "privacy policy" in text or ("privacy" in href and "policy" in href):
                found = True
                break

        # If not found on the homepage, try a common URL.
        if not found:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            privacy_url = base + "/privacy"
            r = requests.get(privacy_url, timeout=5)
            if r.status_code == 200:
                found = True

        if found:
            score = 10
            details = "Privacy policy detected."
        else:
            score = 1
            details = "Privacy policy not detected."

        return f"Privacy Policy Scan score: {score}/10 ({details})"
    except Exception as e:
        return f"Error in Privacy Policy Scan: {str(e)}"

# For testing:
#if __name__ == "__main__":
#    test_url = "https://www.example.com/"
#    print(check_privacy_policy(test_url))
