import requests
import argparse
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Known JavaScript libraries and CMS frameworks with regex patterns for version detection
LIBRARY_PATTERNS = {
    "jQuery": r"jquery-([\d.]+)\.min\.js",
    "Bootstrap": r"bootstrap-([\d.]+)\.min\.js",
    "Angular": r"angular\.min\.js\?v=([\d.]+)",
    "Vue.js": r"vue@([\d.]+)/vue\.global\.js",
    "React": r"react@([\d.]+)/react\.production\.min\.js",
    "WordPress": r"content=\"WordPress ([\d.]+)\"",
    "Joomla": r"/media/system/js/mootools-core\.js\?([\d.]+)",
    "Drupal": r"Drupal\.settings = \{.*version: '([\d.]+)'.*\}"
}

# Score deductions for outdated versions
SCORE_DEDUCTIONS = {
    "outdated_library": 3,
    "outdated_cms": 4,
    "missing_version_info": 2,
}

# API for checking known vulnerabilities (National Vulnerability Database)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword="

def get_page_content(url):
    """
    Fetches the HTML content of a webpage.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"[Error] Could not retrieve page content for {url}: {e}")
        return None

def detect_outdated_libraries(html):
    """
    Scans for outdated JavaScript libraries and CMS versions.
    Returns a dictionary of detected versions.
    """
    detected_versions = {}
    soup = BeautifulSoup(html, "html.parser")

    # Search for JavaScript libraries in script tags.
    for script in soup.find_all("script", src=True):
        script_src = script["src"]
        for lib, pattern in LIBRARY_PATTERNS.items():
            match = re.search(pattern, script_src)
            if match:
                detected_versions[lib] = match.group(1)

    # Search for CMS versions in meta tags.
    for meta in soup.find_all("meta"):
        content = meta.get("content", "")
        for cms, pattern in LIBRARY_PATTERNS.items():
            match = re.search(pattern, content)
            if match:
                detected_versions[cms] = match.group(1)

    return detected_versions

def check_vulnerabilities(technologies):
    """
    Queries the NVD API for known vulnerabilities related to detected versions.
    Returns a tuple (final_score, details_list).
    """
    base_score = 10
    details = []

    for tech, version in technologies.items():
        query = f"{tech} {version}"
        print(f"🔍 Checking for vulnerabilities related to: {query}")
        
        try:
            response = requests.get(NVD_API_URL + query, timeout=10)
            data = response.json()
            
            if "result" in data and "CVE_Items" in data["result"]:
                cve_items = data["result"]["CVE_Items"]
                if cve_items:
                    # For each vulnerability found, deduct a fixed amount.
                    for cve in cve_items:
                        severity = cve.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "unknown").lower()
                        score_deduction = SCORE_DEDUCTIONS.get("outdated_library", 3)
                        base_score -= score_deduction
                        cve_id = cve["cve"]["CVE_data_meta"]["ID"]
                        details.append(f"❌ {tech}: {cve_id} ({severity.capitalize()})")
        except requests.RequestException as e:
            print(f"[Error] Could not retrieve CVE data: {e}")

    final_score = max(1, min(10, base_score))
    if final_score == 10:
        details.append("✅ No known vulnerabilities detected for identified plugins/libraries.")
    elif final_score < 5:
        details.append("⚠️ High risk: The site has outdated or vulnerable libraries!")
    else:
        details.append("⚠️ Moderate risk: Some detected plugins have security issues.")

    return final_score, details

def get_base_url(url):
    """
    Extracts the base URL from a given URL, ensuring it uses https://.
    """
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def main():
    parser = argparse.ArgumentParser(description="Passive Outdated Plugin Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    base_url = get_base_url(args.url)
    print(f"🔍 Scanning for outdated plugins on: {base_url}\n")

    html = get_page_content(base_url)
    if not html:
        print("❌ Failed to retrieve page content.")
        return

    detected_plugins = detect_outdated_libraries(html)
    print(f"🔎 Detected Technologies: {detected_plugins}")

    if not detected_plugins:
        print("✅ No detectable outdated plugins found.")
        return

    score, details = check_vulnerabilities(detected_plugins)

    print("\n--- 🔍 Outdated Plugin Security Report ---")
    for line in details:
        print(f" - {line}")

    print("\n--- 🔢 Security Score ---")
    print(f"Security Score: {score} / 10")

if __name__ == "__main__":
    main()

# Wrapper function for integration into the combined scanner.
def analyze_outdated_plugins(url):
    """
    Wrapper that analyzes outdated plugins for the given URL.
    Returns a tuple: (final_score, details)
    """
    html = get_page_content(url)
    if not html:
        return 1, ["❌ Could not retrieve page content."]
    detected_plugins = detect_outdated_libraries(html)
    if not detected_plugins:
        return 10, "No detectable outdated plugins found."
    score, details = check_vulnerabilities(detected_plugins)
    return score, details
