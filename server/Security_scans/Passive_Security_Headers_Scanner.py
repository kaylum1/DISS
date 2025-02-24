# server/Security_scans/Passive_Security_Headers_Scanner.py
import requests
import argparse
from urllib.parse import urlparse

# Headers that should be present and their recommended values
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": ["DENY", "SAMEORIGIN"],
    "X-XSS-Protection": "1; mode=block",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": [
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin"
    ],
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
}

# Score deduction for missing or weak headers
SCORE_DEDUCTIONS = {
    "missing": 2,
    "weak": 1,
}

def get_headers(url):
    """
    Sends a HEAD request to fetch response headers.
    """
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.headers
    except requests.RequestException as e:
        print(f"[Error] Could not retrieve headers for {url}: {e}")
        return {}

def analyze_headers(headers):
    """
    Evaluates security headers and assigns a security score.
    """
    base_score = 10
    details = []

    for header, recommended_value in SECURITY_HEADERS.items():
        if header not in headers:
            base_score -= SCORE_DEDUCTIONS["missing"]
            details.append(f"❌ Missing: {header}")
        else:
            value = headers[header]
            if isinstance(recommended_value, list):  # For headers with multiple acceptable values
                if value not in recommended_value:
                    base_score -= SCORE_DEDUCTIONS["weak"]
                    details.append(f"⚠️ Weak: {header} → {value} (Should be one of {recommended_value})")
                else:
                    details.append(f"✅ Secure: {header} → {value}")
            else:
                if recommended_value not in value:
                    base_score -= SCORE_DEDUCTIONS["weak"]
                    details.append(f"⚠️ Weak: {header} → {value} (Should contain '{recommended_value}')")
                else:
                    details.append(f"✅ Secure: {header} → {value}")

    final_score = max(1, min(10, base_score))
    return final_score, details

def get_base_url(url):
    """
    Extracts the base URL from a given URL (ensuring it has https://).
    """
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def main():
    parser = argparse.ArgumentParser(description="Passive Security Headers Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    base_url = get_base_url(args.url)
    print(f"🔍 Scanning security headers for: {base_url}\n")

    headers = get_headers(base_url)
    if not headers:
        print("❌ Failed to retrieve headers.")
        return

    score, details = analyze_headers(headers)

    print("\n--- 🛡 Security Headers Report ---")
    for line in details:
        print(f" - {line}")

    print("\n--- 🔢 Security Score ---")
    print(f"Security Score: {score} / 10")
    if score < 5:
        print("⚠️ The website is missing critical security headers!")
    elif score < 8:
        print("⚠️ The website has some weaknesses in security headers. Improvements recommended.")
    else:
        print("✅ The website appears to have strong security headers.")

if __name__ == "__main__":
    main()

# NEW: Wrapper function for integration into the combined scanner.
def analyze_security_headers(url):
    """
    Wrapper function that:
    - Extracts the base URL,
    - Retrieves the headers via a HEAD request,
    - Analyzes them,
    and returns a tuple: (final_score, details).
    """
    base_url = get_base_url(url)
    headers = get_headers(base_url)
    if not headers:
        return 1, ["❌ Failed to retrieve headers."]
    return analyze_headers(headers)
