# server/Privacy_scan/tracker_detection_scan.py

import requests
from bs4 import BeautifulSoup

def check_tracker_detection(url):
    """
    Scans the website for known tracker scripts.
    
    Method:
      - Fetch the homepage HTML.
      - Parse and search for known tracker domains in tags (script, iframe, img).
    
    Known tracker domains (sample list):
      - google-analytics.com
      - googletagmanager.com
      - facebook.com/tr
      - doubleclick.net
      - scorecardresearch.com
    
    Scoring:
      - Starts at 10 if no trackers are found.
      - For each distinct tracker found, subtract 2 points (minimum score is 1).
    
    Returns:
      A string with the final score and details of any trackers detected.
    """
    try:
        tracker_domains = [
            "google-analytics.com",
            "googletagmanager.com",
            "facebook.com/tr",
            "doubleclick.net",
            "scorecardresearch.com"
        ]
        response = requests.get(url, timeout=10)
        html = response.text.lower()
        soup = BeautifulSoup(html, "html.parser")
        
        found_trackers = set()
        for tag in soup.find_all(["script", "iframe", "img"]):
            src = tag.get("src", "")
            if src:
                for tracker in tracker_domains:
                    if tracker in src:
                        found_trackers.add(tracker)
        
        count = len(found_trackers)
        score = max(1, 10 - (2 * count))
        details = f"Found trackers: {', '.join(found_trackers)}" if found_trackers else "No trackers detected."
        return f"Tracker Detection Scan score: {score}/10 ({details})"
    except Exception as e:
        return f"Error in Tracker Detection Scan: {str(e)}"

# For testing:
#if __name__ == "__main__":
 #   test_url = "https://www.example.com/"
 #   print(check_tracker_detection(test_url))
