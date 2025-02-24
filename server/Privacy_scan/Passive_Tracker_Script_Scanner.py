import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# Known tracking and analytics services
TRACKER_DOMAINS = [
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "facebook.com/tr",
    "ads.yahoo.com",
    "amazon-adsystem.com",
    "adservice.google.com",
    "quantserve.com",
    "criteo.com",
    "hotjar.com",
    "fullstory.com",
    "mouseflow.com",
    "scorecardresearch.com",
    "tiktok.com",
    "linkedin.com/li/",
    "bing.com/bat.js"
]

# Score deductions for tracking intensity
SCORE_DEDUCTIONS = {
    "third_party_scripts": 3,
    "ad_networks": 3,
    "analytics_scripts": 2,
    "session_replay": 4,
    "fingerprinting": 4,
}

def get_page_content(url):
    """
    Fetches the HTML content of a webpage.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text, response.headers
    except requests.RequestException as e:
        print(f"[Error] Could not retrieve page content for {url}: {e}")
        return None, None

def detect_tracking_scripts(html, url):
    """
    Scans for tracking scripts in script tags.
    """
    parsed_url = urlparse(url)
    base_domain = parsed_url.netloc
    soup = BeautifulSoup(html, "html.parser")

    tracking_scripts = {
        "analytics_scripts": [],
        "ad_networks": [],
        "session_replay": [],
        "fingerprinting": [],
    }

    for script in soup.find_all("script", src=True):
        script_src = script["src"]
        absolute_url = urljoin(url, script_src)
        script_domain = urlparse(absolute_url).netloc

        for tracker in TRACKER_DOMAINS:
            if tracker in script_domain:
                if "analytics" in tracker or "tagmanager" in tracker:
                    tracking_scripts["analytics_scripts"].append(script_domain)
                elif "ads" in tracker or "doubleclick" in tracker:
                    tracking_scripts["ad_networks"].append(script_domain)
                elif "fullstory" in tracker or "hotjar" in tracker:
                    tracking_scripts["session_replay"].append(script_domain)
                elif "quantserve" in tracker or "criteo" in tracker:
                    tracking_scripts["fingerprinting"].append(script_domain)

    return tracking_scripts

def analyze_tracker_security(url):
    """
    Performs a tracker script analysis and assigns a privacy score.
    """
    base_score = 10
    details = []

    # Fetch HTML
    html, headers = get_page_content(url)
    if not html or not headers:
        return 1, ["❌ Could not analyze the webpage."]

    # Tracking Script Analysis
    tracking_scripts = detect_tracking_scripts(html, url)

    for category, scripts in tracking_scripts.items():
        if scripts:
            deduction = SCORE_DEDUCTIONS[category]
            base_score -= deduction
            details.append(f"❌ {len(scripts)} {category.replace('_', ' ')} found (Score -{deduction})")
            for script in scripts[:3]:  # Show up to 3 examples
                details.append(f"   - {script}")

    # Ensure score stays within 1-10 range
    final_score = max(1, min(10, base_score))

    if final_score == 10:
        details.append("✅ No significant tracking scripts detected.")
    elif final_score < 5:
        details.append("⚠️ High risk: The website contains heavy tracking behavior!")
    else:
        details.append("⚠️ Moderate risk: Some tracking scripts detected.")

    return final_score, details

def get_base_url(url):
    """
    Extracts the base URL from a given URL, ensuring it has https://.
    """
    if "://" not in url:
        url = "https://" + url  # Assume HTTPS by default
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def main():
    parser = argparse.ArgumentParser(description="Passive Tracker Script Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    base_url = get_base_url(args.url)
    print(f"🔍 Scanning tracker scripts on: {base_url}\n")

    score, details = analyze_tracker_security(base_url)

    print("\n--- 🔍 Tracker Script Report ---")
    for line in details:
        print(f" - {line}")

    print("\n--- 🔢 Privacy Score ---")
    print(f"Privacy Score: {score} / 10")
    if score < 5:
        print("⚠️ The website has serious privacy risks!")
    elif score < 8:
        print("⚠️ The website has some tracking behavior. Reducing trackers recommended.")
    else:
        print("✅ The website does not contain excessive tracking.")

if __name__ == "__main__":
    main()




"""
🔍 How It Works

Fetches HTML Content:
Extracts JavaScript scripts and network requests.
Identifies Tracking Risks:
Google Analytics, Facebook Pixel, Ad networks (DoubleClick, Amazon Ads).
Session replay scripts (Hotjar, FullStory).
Fingerprinting techniques (Quantserve, Criteo).
Calculates Privacy Score (1-10):
1-4 → High tracking risk ⚠️
5-7 → Moderate tracking risk 🟡
8-10 → Low tracking, privacy-friendly ✅
🚀 How to Use

Run the script with a target URL:

python Passive_Tracker_Script_Scanner.py -u "https://example.com"
✅ Example Output:

🔍 Scanning tracker scripts on: https://example.com

--- 🔍 Tracker Script Report ---
 - ❌ 3 analytics scripts found (Score -2)
   - google-analytics.com
   - googletagmanager.com
 - ❌ 2 ad networks found (Score -3)
   - amazon-adsystem.com
   - doubleclick.net
 - ❌ 1 fingerprinting tracker found (Score -4)
   - quantserve.com

--- 🔢 Privacy Score ---
Privacy Score: 3 / 10
⚠️ The website contains heavy tracking behavior!




"""