import requests
import argparse
import re
from urllib.parse import urlparse

# Common CSP directives that should be present
ESSENTIAL_CSP_DIRECTIVES = [
    "default-src",
    "script-src",
    "object-src",
    "frame-ancestors"
]

# Risky CSP configurations that weaken security
CSP_RISK_PATTERNS = {
    "wildcard": r"\*",
    "unsafe_inline": r"unsafe-inline",
    "unsafe_eval": r"unsafe-eval"
}

# Score deductions for weak CSP configurations
SCORE_DEDUCTIONS = {
    "missing_directive": 3,
    "wildcard": 3,
    "unsafe_inline": 4,
    "unsafe_eval": 4,
    "external_scripts": 2,
}

def get_csp_header(headers):
    """
    Extracts the Content-Security-Policy header from the response headers.
    """
    return headers.get("Content-Security-Policy", None)

def detect_missing_directives(csp):
    """
    Checks if essential CSP directives are missing.
    """
    missing = [directive for directive in ESSENTIAL_CSP_DIRECTIVES if directive not in csp]
    return missing

def detect_risky_patterns(csp):
    """
    Identifies dangerous CSP patterns like 'unsafe-inline', 'unsafe-eval', and wildcard '*'.
    """
    risks = []
    for risk, pattern in CSP_RISK_PATTERNS.items():
        if re.search(pattern, csp):
            risks.append(risk)
    return risks

def detect_external_script_sources(csp):
    """
    Identifies external script sources in 'script-src' that could introduce risks.
    """
    external_sources = []
    script_src_match = re.search(r"script-src ([^;]+)", csp)
    if script_src_match:
        script_sources = script_src_match.group(1).split()
        for source in script_sources:
            if source.startswith("http") and "self" not in source:
                external_sources.append(source)
    return external_sources

def analyze_csp_security(url):
    """
    Fetches the CSP header, analyzes its security, and assigns a security score.
    """
    base_score = 10
    details = []

    # Fetch headers
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
    except requests.RequestException as e:
        print(f"[Error] Could not retrieve headers for {url}: {e}")
        return 1, ["❌ Could not analyze the webpage."]

    # Get CSP Header
    csp = get_csp_header(headers)
    if not csp:
        return 1, ["❌ No Content-Security-Policy (CSP) header found. This is a major security risk!"]

    # Missing Directives Analysis
    missing_directives = detect_missing_directives(csp)
    if missing_directives:
        base_score -= SCORE_DEDUCTIONS["missing_directive"]
        details.append(f"⚠️ Missing essential CSP directives: {', '.join(missing_directives)} (Score -{SCORE_DEDUCTIONS['missing_directive']})")

    # Risky CSP Pattern Analysis
    risky_patterns = detect_risky_patterns(csp)
    for risk in risky_patterns:
        base_score -= SCORE_DEDUCTIONS[risk]
        details.append(f"❌ Weak CSP setting detected: {risk.replace('_', ' ')} (Score -{SCORE_DEDUCTIONS[risk]})")

    # External Script Source Analysis
    external_scripts = detect_external_script_sources(csp)
    if external_scripts:
        base_score -= SCORE_DEDUCTIONS["external_scripts"]
        details.append(f"⚠️ External script sources detected: {', '.join(external_scripts[:3])}... (Score -{SCORE_DEDUCTIONS['external_scripts']})")

    # Ensure score stays within 1-10 range
    final_score = max(1, min(10, base_score))

    if final_score == 10:
        details.append("✅ Strong CSP detected. No significant security risks found.")
    elif final_score < 5:
        details.append("⚠️ High risk: The website has serious CSP misconfigurations!")
    else:
        details.append("⚠️ Moderate risk: Some CSP security improvements are needed.")

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
    parser = argparse.ArgumentParser(description="Passive CSP Violation Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    base_url = get_base_url(args.url)
    print(f"🔍 Scanning CSP security for: {base_url}\n")

    score, details = analyze_csp_security(base_url)

    print("\n--- 🔍 CSP Security Report ---")
    for line in details:
        print(f" - {line}")

    print("\n--- 🔢 Security Score ---")
    print(f"Security Score: {score} / 10")
    if score < 5:
        print("⚠️ The website has serious CSP security risks!")
    elif score < 8:
        print("⚠️ The website has some CSP misconfigurations. Fixing recommended.")
    else:
        print("✅ The website has a strong CSP policy.")

if __name__ == "__main__":
    main()
