import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse

def analyze_dnt_support(url):
    """
    Passively analyzes whether a website indicates support for Do Not Track (DNT).

    This scan:
      - Sends a GET request with a "DNT: 1" header.
      - Checks if the response includes a DNT header.
      - Looks for a meta tag with name "dnt" in the HTML.
      - Scans the HTML for key phrases (e.g., "honor do not track") that suggest the site supports DNT.

    Returns:
      (final_score, details)
      
      final_score: An integer between 1 and 10 (10 means strong indication of DNT support).
      details: A list of strings describing each finding.
    """
    try:
        response = requests.get(url, timeout=10, headers={"DNT": "1"})
        headers = response.headers
        html = response.text
    except Exception as e:
        return 1, [f"Error fetching page: {e}"]

    details = []
    deduction = 0

    # --- Check Response Headers ---
    if "DNT" in headers:
        details.append("Response includes a 'DNT' header.")
    else:
        details.append("No 'DNT' header in the response.")
        deduction += 1

    # --- Check for Meta Tag ---
    soup = BeautifulSoup(html, "html.parser")
    meta_dnt = soup.find("meta", attrs={"name": "dnt"})
    if meta_dnt:
        content = meta_dnt.get("content", "").strip().lower()
        details.append(f"Found meta tag for DNT with content '{content}'.")
        if content in {"1", "true"}:
            details.append("Meta tag clearly indicates support for Do Not Track.")
        else:
            details.append("Meta tag present but content does not clearly indicate support.")
            deduction += 1
    else:
        details.append("No meta tag for DNT found in the HTML.")
        deduction += 2

    # --- Search for Key Phrases ---
    phrases = [
        r"honor do not track",
        r"respects do not track",
        r"supports do not track",
        r"do not track policy",
        r"dnt is honored"
    ]
    found_phrase = False
    for phrase in phrases:
        if re.search(phrase, html, re.IGNORECASE):
            details.append(f"Found phrase indicating DNT support: '{phrase}'.")
            found_phrase = True
            break
    if not found_phrase:
        details.append("No explicit phrase indicating Do Not Track support found in the page content.")
        deduction += 3

    # --- Final Score Computation ---
    final_score = max(1, min(10, 10 - deduction))
    if final_score == 10:
        details.append("✅ Strong indication that the site supports Do Not Track.")
    elif final_score < 5:
        details.append("⚠️ High risk: The site does not clearly indicate support for Do Not Track.")
    else:
        details.append("⚠️ Moderate risk: Some indications of DNT support are present, but improvement is needed.")

    return final_score, details

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Passive Do Not Track Support Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()
    score, details = analyze_dnt_support(args.url)
    print(f"Final Score: {score}/10")
    for line in details:
        print(line)
