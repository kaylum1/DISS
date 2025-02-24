import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# A dictionary of common third-party tracking domains and their associated deduction points.
TRACKER_DOMAINS = {
    "google-analytics.com": 1,
    "googletagmanager.com": 1,
    "doubleclick.net": 2,
    "facebook.com": 2,
    "twitter.com": 1,
    "hotjar.com": 2,
    "mixpanel.com": 2,
    "segment.com": 2,
    "quantserve.com": 2,
    "scorecardresearch.com": 2,
    "adroll.com": 2,
    "chartbeat.com": 1,
    "criteo.com": 1,
    "adobedtm.com": 1,
    "piwik.pro": 1,
    "addthis.com": 1,
    "zendesk.com": 1
}

def analyze_third_party_data_collection(url):
    """
    Passively scans a webpage to detect third-party data collection by inspecting
    external resource URLs and inline script content for known tracking domains.
    
    Returns:
      (final_score, details)
      
    - final_score: An integer from 1 to 10, where 10 indicates no evidence of third-party tracking.
    - details: A list of strings describing detected trackers and overall risk.
    """
    try:
        response = requests.get(url, timeout=10)
        html = response.text
    except Exception as e:
        return 1, [f"Error fetching page: {str(e)}"]

    soup = BeautifulSoup(html, "html.parser")
    page_domain = urlparse(url).netloc.lower()
    
    detected = []  # To hold detection details
    total_deduction = 0

    def check_external_url(external_url):
        nonlocal total_deduction
        parsed = urlparse(external_url)
        domain = parsed.netloc.lower()
        # Only consider if the external domain is not the same as the current page
        if domain and domain != page_domain:
            for tracker, deduction in TRACKER_DOMAINS.items():
                if tracker in domain:
                    detected.append(f"Tracker detected: '{tracker}' in {external_url} (deduction {deduction})")
                    total_deduction += deduction
                    break

    # Check external resources in <script> tags
    for script in soup.find_all("script", src=True):
        src = script["src"]
        parsed = urlparse(src)
        if parsed.netloc:
            check_external_url(src)
    
    # Check external resources in <iframe> tags
    for iframe in soup.find_all("iframe", src=True):
        src = iframe["src"]
        parsed = urlparse(src)
        if parsed.netloc:
            check_external_url(src)
    
    # Check external resources in <img> tags
    for img in soup.find_all("img", src=True):
        src = img["src"]
        parsed = urlparse(src)
        if parsed.netloc:
            check_external_url(src)
    
    # Additionally, scan inline script content for any mention of known trackers.
    for script in soup.find_all("script"):
        # Only check scripts without a src (inline code)
        if not script.has_attr("src"):
            content = script.get_text().lower()
            for tracker, deduction in TRACKER_DOMAINS.items():
                if tracker in content:
                    detected.append(f"Inline tracker snippet detected for '{tracker}' (deduction {deduction})")
                    total_deduction += deduction
                    break

    # Compute final score: base score is 10 minus the total deduction.
    final_score = max(1, min(10, 10 - total_deduction))
    if final_score == 10:
        detected.append("✅ No significant third-party data collection detected.")
    elif final_score < 5:
        detected.append("⚠️ High risk: Many third-party trackers detected!")
    else:
        detected.append("⚠️ Moderate risk: Some third-party trackers detected.")

    return final_score, detected

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Passive Third-Party Data Collection Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()
    score, details = analyze_third_party_data_collection(args.url)
    print(f"Final Score: {score}/10")
    for detail in details:
        print(detail)
