#server/Security_scans/Passive_XSS_Security_Scanner.py

import requests
import argparse
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

# JavaScript functions that are commonly exploited for XSS
XSS_RISK_FUNCTIONS = [
    "eval(",
    "document.write(",
    "innerHTML",
    "setTimeout(",
    "setInterval(",
    "unescape(",
    "location.href=",
    "location.assign(",
    "localStorage.setItem(",
    "sessionStorage.setItem(",
    "Function("
]

# Score deductions for vulnerabilities
SCORE_DEDUCTIONS = {
    "risky_js": 3,  # Insecure JavaScript functions found
    "missing_csp": 3,  # Content-Security-Policy not set
    "missing_xss_protection": 2,  # No X-XSS-Protection header
    "reflected_params": 2,  # URL parameters reflected in response
    "inline_scripts": 2,  # Potentially dangerous inline scripts
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

def detect_risky_js(html):
    """
    Scans JavaScript code for dangerous functions.
    """
    found_risks = []
    for function in XSS_RISK_FUNCTIONS:
        if function in html:
            found_risks.append(function)
    return found_risks

def detect_security_headers(headers):
    """
    Checks for essential security headers that mitigate XSS.
    """
    missing_headers = []
    if "Content-Security-Policy" not in headers:
        missing_headers.append("Content-Security-Policy")
    if "X-XSS-Protection" not in headers:
        missing_headers.append("X-XSS-Protection")
    return missing_headers

def detect_reflected_params(url, html):
    """
    Identifies URL parameters that are reflected in the page content (potential XSS risk).
    """
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    
    reflected = [key for key, values in params.items() if any(value in html for value in values)]
    return reflected

def detect_inline_scripts(html):
    """
    Identifies inline JavaScript, which can be a potential XSS risk.
    """
    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script")
    
    inline_scripts = [script.string for script in scripts if script.string]
    return inline_scripts

def analyze_xss_security(url):
    """
    Performs an XSS security risk analysis and assigns a security score.
    Returns a tuple: (final_score, details_string)
    """
    base_score = 10
    details = []

    # Fetch HTML and headers
    html, headers = get_page_content(url)
    if not html or not headers:
        return 1, "❌ Could not analyze the webpage."

    # JavaScript Vulnerability Analysis
    risky_js = detect_risky_js(html)
    if risky_js:
        base_score -= SCORE_DEDUCTIONS["risky_js"]
        details.append(f"⚠️ Insecure JavaScript functions found: {', '.join(risky_js)} (Score -{SCORE_DEDUCTIONS['risky_js']})")

    # Security Header Analysis
    missing_headers = detect_security_headers(headers)
    if missing_headers:
        deduction = sum(SCORE_DEDUCTIONS[header.lower()] for header in missing_headers if header.lower() in SCORE_DEDUCTIONS)
        base_score -= deduction
        details.append(f"⚠️ Missing security headers: {', '.join(missing_headers)}")

    # Reflected Parameter Analysis
    reflected_params = detect_reflected_params(url, html)
    if reflected_params:
        base_score -= SCORE_DEDUCTIONS["reflected_params"]
        details.append(f"⚠️ Reflected user input detected: {', '.join(reflected_params)} (Score -{SCORE_DEDUCTIONS['reflected_params']})")

    # Inline JavaScript Analysis
    inline_scripts = detect_inline_scripts(html)
    if inline_scripts:
        base_score -= SCORE_DEDUCTIONS["inline_scripts"]
        details.append(f"⚠️ {len(inline_scripts)} inline JavaScript snippets found (Score -{SCORE_DEDUCTIONS['inline_scripts']})")

    # Ensure score stays within 1-10 range
    final_score = max(1, min(10, base_score))

    if final_score == 10:
        details.append("✅ No significant XSS risks detected.")
    elif final_score < 5:
        details.append("⚠️ High risk: The website has serious XSS vulnerabilities!")
    else:
        details.append("⚠️ Moderate risk: Some XSS security improvements are needed.")

    # Return the numeric score and a joined string of details.
    return final_score, "; ".join(details)

def get_base_url(url):
    """
    Extracts the base URL from a given URL, ensuring it has https://.
    """
    if "://" not in url:
        url = "https://" + url  # Assume HTTPS by default
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def main():
    import sys
    parser = argparse.ArgumentParser(description="Passive XSS Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    base_url = get_base_url(args.url)
    print(f"🔍 Scanning XSS security for: {base_url}\n")

    score, details = analyze_xss_security(base_url)

    print("\n--- 🔍 XSS Security Report ---")
    for line in details.split("; "):
        print(f" - {line}")

    print("\n--- 🔢 Security Score ---")
    print(f"Security Score: {score} / 10")
    if score < 5:
        print("⚠️ The website has serious XSS vulnerabilities!")
    elif score < 8:
        print("⚠️ The website has some XSS security risks. Fixing recommended.")
    else:
        print("✅ The website appears to be well-protected against XSS.")

if __name__ == "__main__":
    main()
