# server/Security_scans/Passive_Privacy_and_Tracker_Audit_Scanner.py

import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# List of common trackers, ad networks, and privacy-invasive services
KNOWN_TRACKERS = [
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "facebook.com/tr",
    "ads.yahoo.com",
    "amazon-adsystem.com",
    "adservice.google.com",
    "clicksgear.com",
    "quantserve.com",
    "criteo.com",
    "mathtag.com",
    "scorecardresearch.com",
    "hotjar.com",
    "fullstory.com",  # Session recording service
    "mouseflow.com"   # Session tracking
]

# Score deductions per privacy risk
SCORE_DEDUCTIONS = {
    "trackers": 3,
    "ad_networks": 2,
    "third_party_cookies": 2,
    "session_replay": 4,
    "privacy_headers_missing": 2,
}

def get_page_content(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text, response.headers
    except requests.RequestException as e:
        print(f"[Error] Could not retrieve page content for {url}: {e}")
        return None, None

def detect_trackers(url, html):
    parsed_url = urlparse(url)
    base_domain = parsed_url.netloc
    soup = BeautifulSoup(html, "html.parser")

    tracker_issues = {
        "trackers": [],
        "ad_networks": [],
        "session_replay": []
    }

    for script in soup.find_all("script", src=True):
        script_src = script["src"]
        absolute_url = urljoin(url, script_src)
        parsed_script_url = urlparse(absolute_url).netloc

        for tracker in KNOWN_TRACKERS:
            if tracker in parsed_script_url:
                if "fullstory.com" in tracker or "hotjar.com" in tracker:
                    tracker_issues["session_replay"].append(absolute_url)
                elif "ads" in tracker or "doubleclick.net" in tracker:
                    tracker_issues["ad_networks"].append(absolute_url)
                else:
                    tracker_issues["trackers"].append(absolute_url)

    return tracker_issues

def detect_privacy_headers(headers):
    privacy_headers = {
        "DNT": headers.get("DNT", "Missing"),
        "GPC": headers.get("Sec-GPC", "Missing"),
        "Referrer-Policy": headers.get("Referrer-Policy", "Missing")
    }
    missing_headers = [key for key, value in privacy_headers.items() if value == "Missing"]
    return privacy_headers, missing_headers

def analyze_privacy(url):
    base_score = 10
    details = []

    html, headers = get_page_content(url)
    if not html or not headers:
        return 1, ["❌ Could not analyze the webpage."]

    tracker_issues = detect_trackers(url, html)

    for category, trackers in tracker_issues.items():
        if trackers:
            deduction = min(len(trackers) * SCORE_DEDUCTIONS[category], 5)
            base_score -= deduction
            details.append(f"❌ {len(trackers)} {category.replace('_', ' ')} detected (Score -{deduction})")
            for tracker in trackers[:3]:
                details.append(f"   - {tracker}")

    privacy_headers, missing_headers = detect_privacy_headers(headers)
    if missing_headers:
        base_score -= SCORE_DEDUCTIONS["privacy_headers_missing"]
        details.append(f"⚠️ Missing privacy headers: {', '.join(missing_headers)} (Score -{SCORE_DEDUCTIONS['privacy_headers_missing']})")
    else:
        details.append("✅ Privacy headers (DNT, GPC, Referrer-Policy) are properly set.")

    final_score = max(1, min(10, base_score))

    if final_score == 10:
        details.append("✅ No significant tracking or privacy issues detected.")
    elif final_score < 5:
        details.append("⚠️ High privacy risk: The website has serious tracking concerns!")
    else:
        details.append("⚠️ Moderate risk: Some privacy improvements are recommended.")

    return final_score, details

# Wrapper function for integration.
def analyze_privacy_and_tracker_audit(url):
    return analyze_privacy(url)

def main():
    parser = argparse.ArgumentParser(description="Passive Privacy & Tracker Audit Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    base_url = args.url if "://" in args.url else "https://" + args.url
    print(f"🔍 Scanning privacy & tracker audit for: {base_url}\n")

    score, details = analyze_privacy(base_url)

    print("\n--- 🔍 Privacy & Tracker Report ---")
    for line in details:
        print(f" - {line}")

    print("\n--- 🔢 Privacy Score ---")
    print(f"Privacy Score: {score} / 10")
    if score < 5:
        print("⚠️ The website has serious privacy and tracking concerns!")
    elif score < 8:
        print("⚠️ The website has some privacy risks. Fixing recommended.")
    else:
        print("✅ The website appears to respect user privacy.")

if __name__ == "__main__":
    main()
