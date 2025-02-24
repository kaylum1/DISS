# server/Security_scans/Passive_Third_Party_Script_Evaluation_Scanner.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# List of known risky third-party domains (expandable)
KNOWN_RISKY_DOMAINS = [
    "coinhive.com",         # Cryptocurrency mining scripts
    "googletagmanager.com",   # Common tracker
    "doubleclick.net",        # Ad network
    "adservice.google.com",   # Ad services
    "popads.net",             # Popup ads network
    "clicksgear.com"          # Known malware distributor
]

# Score deductions for different risk levels
SCORE_DEDUCTIONS = {
    "insecure": 3,       # Script loaded over HTTP
    "third_party": 2,    # Script from external domain
    "risky_domain": 4,   # Script from a known risky domain
}

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

def detect_third_party_scripts(url, html):
    """
    Scans a webpage for third-party JavaScript files and evaluates their security.
    Returns a dictionary categorizing flagged scripts.
    """
    parsed_url = urlparse(url)
    base_domain = parsed_url.netloc
    soup = BeautifulSoup(html, "html.parser")

    script_issues = {
        "insecure": [],
        "third_party": [],
        "risky_domain": []
    }

    for script in soup.find_all("script", src=True):
        script_src = script["src"]
        script_url = urljoin(url, script_src)
        parsed_script_url = urlparse(script_url)

        if parsed_script_url.scheme == "http":
            script_issues["insecure"].append(script_url)

        if parsed_script_url.netloc and parsed_script_url.netloc != base_domain:
            script_issues["third_party"].append(script_url)

            for risky_domain in KNOWN_RISKY_DOMAINS:
                if risky_domain in parsed_script_url.netloc:
                    script_issues["risky_domain"].append(script_url)
                    if script_url in script_issues["third_party"]:
                        script_issues["third_party"].remove(script_url)

    return script_issues

def calculate_score(script_issues):
    """
    Assigns a security score (1-10) based on script security risks.
    """
    base_score = 10
    total_deduction = 0
    details = []

    for category, scripts in script_issues.items():
        count = len(scripts)
        if count > 0:
            deduction = min(count * SCORE_DEDUCTIONS[category], 5)  # Cap deductions per category
            total_deduction += deduction
            details.append(f"❌ {count} {category.replace('_', ' ')} scripts detected (Score -{deduction})")
            for script in scripts[:3]:  # Show up to 3 examples
                details.append(f"   - {script}")

    final_score = max(1, base_score - total_deduction)

    if final_score == 10:
        details.append("✅ No third-party script security risks detected.")
    elif final_score < 5:
        details.append("⚠️ High risk: The site has significant third-party script security issues!")
    else:
        details.append("⚠️ Moderate risk: Some third-party scripts could be improved.")

    return final_score, details

def get_base_url(url):
    """
    Extracts the base URL from a given URL, ensuring it has https://.
    """
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def analyze_third_party_script_evaluation(url):
    base_url = get_base_url(url)
    html = get_page_content(base_url)
    if not html:
        return 1, ["❌ Failed to retrieve page content."]
    script_issues = detect_third_party_scripts(base_url, html)
    score, details = calculate_score(script_issues)
    return score, details


# Optionally, you may keep main() for command-line usage.
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Passive Third-Party Script Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    base_url = get_base_url(args.url)
    print(f"🔍 Scanning for third-party scripts on: {base_url}\n")

    html = get_page_content(base_url)
    if not html:
        print("❌ Failed to retrieve page content.")
        return

    script_issues = detect_third_party_scripts(base_url, html)
    score, details = calculate_score(script_issues)

    print("\n--- 🔍 Third-Party Script Security Report ---")
    for line in details:
        print(f" - {line}")

    print("\n--- 🔢 Security Score ---")
    print(f"Security Score: {score} / 10")
    if score < 5:
        print("⚠️ The website has serious third-party script security risks!")
    elif score < 8:
        print("⚠️ The website has some script security risks. Fixing recommended.")
    else:
        print("✅ The website appears secure from third-party script vulnerabilities.")

if __name__ == "__main__":
    main()
