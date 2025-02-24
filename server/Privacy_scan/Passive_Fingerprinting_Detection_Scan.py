import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse

# Define common fingerprinting indicators and associated deduction points.
FINGERPRINTING_INDICATORS = {
    "toDataURL": 2,               # Often used in canvas fingerprinting.
    "getContext('2d')": 1,         # Canvas 2D context
    'getContext("2d")': 1,
    "getContext('webgl')": 2,      # WebGL fingerprinting can be more advanced.
    'getContext("webgl")': 2,
    "FingerprintJS": 3,           # Known library
    "Fingerprint2": 3,            # Another popular fingerprinting library
    "clientjs": 2,                # ClientJS library for fingerprinting
    "canvas fingerprint": 2,      # Generic phrase
    "audioContext": 2,            # Audio-based fingerprinting indicator
    "navigator.plugins": 1,       # Plugin enumeration is often used for fingerprinting
    "devicePixelRatio": 1,
    "screen.width": 1,
    "screen.height": 1,
    "screen.colorDepth": 1,
    "timezone": 1,
    "navigator.languages": 1,
    "hardwareConcurrency": 1
}

def analyze_fingerprinting_detection(url):
    """
    Passively scans a webpage to detect fingerprinting and device tracking methods.
    
    The scan analyzes:
      - Inline JavaScript code for fingerprinting function calls or library references.
      - External script URLs for known fingerprinting library names.
    
    Returns:
      (final_score, details)
      
      - final_score: An integer between 1 and 10 (10 indicates no fingerprinting detected).
      - details: A list of strings describing each finding and overall risk.
    """
    try:
        response = requests.get(url, timeout=10)
        html = response.text
    except Exception as e:
        return 1, [f"Error fetching page: {str(e)}"]

    details = []
    total_deduction = 0

    soup = BeautifulSoup(html, "html.parser")
    page_domain = urlparse(url).netloc.lower()

    # Check inline script content for fingerprinting indicators.
    for script in soup.find_all("script"):
        if not script.has_attr("src"):
            content = script.get_text()
            for indicator, deduction in FINGERPRINTING_INDICATORS.items():
                if re.search(indicator, content, re.IGNORECASE):
                    details.append(f"Inline script contains fingerprinting indicator '{indicator}' (deduction {deduction})")
                    total_deduction += deduction

    # Check external script URLs for known fingerprinting libraries.
    for script in soup.find_all("script", src=True):
        src = script["src"]
        # Only consider external URLs if the domain differs from the page's domain.
        parsed = urlparse(src)
        if parsed.netloc and parsed.netloc.lower() != page_domain:
            for indicator, deduction in FINGERPRINTING_INDICATORS.items():
                if re.search(indicator, src, re.IGNORECASE):
                    details.append(f"External script URL '{src}' contains fingerprinting indicator '{indicator}' (deduction {deduction})")
                    total_deduction += deduction
                    break  # Avoid double-counting the same script.

    # Compute the final score.
    final_score = max(1, min(10, 10 - total_deduction))
    if final_score == 10:
        details.append("✅ No significant fingerprinting methods detected.")
    elif final_score < 5:
        details.append("⚠️ High risk: Numerous fingerprinting techniques detected!")
    else:
        details.append("⚠️ Moderate risk: Some fingerprinting techniques detected.")

    return final_score, details

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Passive Fingerprinting Detection Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()
    score, details = analyze_fingerprinting_detection(args.url)
    print(f"Final Score: {score}/10")
    for detail in details:
        print(detail)
