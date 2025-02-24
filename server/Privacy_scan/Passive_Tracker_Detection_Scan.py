import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Define a dictionary of known tracker indicators and their deduction points.
# These can include JavaScript function calls, domain keywords, and generic keywords.
TRACKER_INDICATORS = {
    "ga(": 1,            # Google Analytics
    "gtag(": 1,          # Global site tag for Google Analytics
    "fbq(": 2,           # Facebook Pixel tracking
    "mixpanel": 2,
    "segment": 2,
    "hotjar": 2,
    "clicky": 1,
    "chartbeat": 1,
    "scorecardresearch": 2,
    "adobe-analytics": 2,
    "optimizely": 1,
    "quantserve": 2,
    "criteo": 1,
    "doubleclick": 2,
    "twitter": 1,
    "piwik": 1,
    "matomo": 1,
    "cookiebot": 1,
    "pixel": 1,         # Generic pixel reference
    "tracking": 1       # Generic keyword
}

def analyze_tracker_detection(url):
    """
    Passively scans a webpage for tracker indicators by analyzing:
      - External resource URLs (from <script>, <link>, and <img> tags)
      - Inline script content for known tracking function calls or keywords
      - Cookie names in the response for potential tracking usage

    Returns:
      (final_score, details)
      
      final_score: An integer between 1 and 10 (10 = no trackers detected).
      details: A list of strings describing each finding and overall risk.
    """
    try:
        response = requests.get(url, timeout=10)
        html = response.text
    except Exception as e:
        return 1, [f"Error fetching page: {str(e)}"]

    details = []
    total_deduction = 0

    # Parse the HTML
    soup = BeautifulSoup(html, "html.parser")
    page_domain = urlparse(url).netloc.lower()

    # Function to check a URL (from a tag) against our tracker indicators.
    def check_url(resource_url, tag_type):
        nonlocal total_deduction
        parsed = urlparse(resource_url)
        domain = parsed.netloc.lower()
        # Only analyze external domains (i.e. not the same as the page's domain)
        if domain and domain != page_domain:
            for indicator, deduction in TRACKER_INDICATORS.items():
                if indicator in resource_url.lower():
                    details.append(f"{tag_type} URL '{resource_url}' contains tracker indicator '{indicator}' (deduction {deduction})")
                    total_deduction += deduction
                    break

    # Check external resources in <script> tags (with a src attribute)
    for script in soup.find_all("script", src=True):
        check_url(script["src"], "Script")
    
    # Check external resources in <link> tags
    for link in soup.find_all("link", href=True):
        check_url(link["href"], "Link")
    
    # Check external resources in <img> tags
    for img in soup.find_all("img", src=True):
        check_url(img["src"], "Image")
    
    # Check inline script content for known tracker keywords
    for script in soup.find_all("script"):
        # Only check inline scripts (no src)
        if not script.has_attr("src"):
            content = script.get_text().lower()
            for indicator, deduction in TRACKER_INDICATORS.items():
                if indicator in content:
                    details.append(f"Inline script contains tracker indicator '{indicator}' (deduction {deduction})")
                    total_deduction += deduction
                    break

    # Optionally, check response cookies for tracker-like names.
    for cookie in response.cookies:
        cookie_name = cookie.name.lower()
        for indicator, deduction in TRACKER_INDICATORS.items():
            if indicator in cookie_name:
                details.append(f"Cookie '{cookie.name}' may be used for tracking (deduction {deduction})")
                total_deduction += deduction
                break

    # Compute the final score.
    final_score = max(1, min(10, 10 - total_deduction))
    if final_score == 10:
        details.append("✅ No significant tracker indicators detected.")
    elif final_score < 5:
        details.append("⚠️ High risk: Many tracker indicators detected!")
    else:
        details.append("⚠️ Moderate risk: Some tracker indicators detected.")

    return final_score, details

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Passive Tracker Detection Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()
    score, details = analyze_tracker_detection(args.url)
    print(f"Final Score: {score}/10")
    for detail in details:
        print(detail)
