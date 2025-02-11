# server/Privacy_scan/do_not_track_support_scan.py

import requests
from bs4 import BeautifulSoup

def check_do_not_track_support(url):
    """
    Checks if the website indicates support for Do Not Track.
    
    Method:
      - Fetch the homepage HTML.
      - Parse for meta tags or text containing "do not track".
    
    Scoring:
      - If found: score 8/10.
      - If not found: score 3/10.
    
    Returns:
      A string with the final score and details.
    """
    try:
        response = requests.get(url, timeout=10)
        html = response.text.lower()
        soup = BeautifulSoup(html, "html.parser")
        found = False
        
        # Look for meta tags that might indicate Do Not Track support.
        for meta in soup.find_all("meta"):
            name_attr = meta.get("name", "").lower()
            if name_attr in ["dnt", "do not track"]:
                found = True
                break
        
        # Also perform a basic text search.
        if not found and "do not track" in html:
            found = True
        
        if found:
            score = 8
            details = "Do Not Track support indicators found."
        else:
            score = 3
            details = "Do Not Track support not detected."
        return f"Do Not Track Support Scan score: {score}/10 ({details})"
    except Exception as e:
        return f"Error in Do Not Track Support Scan: {str(e)}"

# For testing:
#if __name__ == "__main__":
#    test_url = "https://www.example.com/"
#    print(check_do_not_track_support(test_url))
