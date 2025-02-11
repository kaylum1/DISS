# server/Security_scans/directory_listing_check_scan.py
import requests
from bs4 import BeautifulSoup

def check_directory_listing(url):
    """
    Performs a directory listing check scan on the given URL.

    Method:
      1. Ensure the URL ends with a slash ("/") to test the directory listing.
      2. Fetch the page using an HTTP GET request.
         - If the server returns a 403 (Forbidden), it likely means directory listing is disabled.
      3. Parse the HTML with BeautifulSoup and look for common indicators of directory listing:
         - The <title> element starts with "Index of" (case-insensitive).
         - The page contains the phrase "Parent Directory".
         - The page contains the phrase "directory listing".
      4. Count the number of such indicators:
         - 0 indicators: assume directory listing is disabled → score 10/10.
         - 1 indicator: score ~7/10.
         - 2 indicators: score ~4/10.
         - 3 or more indicators: score 1/10.
    
    Returns:
      A string in the format:
      "Directory Listing Check Scan score: X/10 (details...)"
    """
    try:
        # Ensure the URL ends with a slash to trigger a directory listing view
        if not url.endswith('/'):
            url = url + '/'

        response = requests.get(url, timeout=10)
        
        # If access is forbidden, we assume directory listing is disabled
        if response.status_code == 403:
            return "Directory Listing Check Scan score: 10/10 (Access forbidden - directory listing disabled)"
        
        html = response.text
        soup = BeautifulSoup(html, "html.parser")
        
        indicators = []
        
        # Indicator 1: Check if the <title> starts with "Index of"
        title_tag = soup.find("title")
        if title_tag and title_tag.get_text().strip().lower().startswith("index of"):
            indicators.append("Title indicates 'Index of'")
        
        # Indicator 2: Look for "Parent Directory" in the page (common in directory listings)
        if "parent directory" in html.lower():
            indicators.append("Contains 'Parent Directory'")
        
        # Indicator 3: Look for "directory listing" in the page content
        if "directory listing" in html.lower():
            indicators.append("Contains 'directory listing'")
        
        indicator_count = len(indicators)
        
        # Calculate final score: if 0 indicators, score is 10; if 1 indicator, ~7; if 2, ~4; if 3 or more, score is 1.
        if indicator_count >= 3:
            final_score = 1
        else:
            final_score = round(10 - indicator_count * 3)  # 0 => 10, 1 => 7, 2 => 4
        
        details = "; ".join(indicators) if indicators else "No directory listing indicators found"
        return f"Directory Listing Check Scan score: {final_score}/10 ({details})"
    
    except Exception as e:
        return f"Error performing directory listing check scan: {str(e)}"


