import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def analyze_referrer_dnt(url):
    """
    Passively analyzes a website's Referrer Policy and Do Not Track (DNT) compliance.

    It does the following:
      - Sends a GET request (with a DNT request header) and inspects the response headers for "Referrer-Policy".
      - Evaluates the Referrer Policy value against best practices.
      - Parses the HTML for a meta tag named "dnt" and checks its content.

    Returns:
      (final_score, details)
      
      - final_score: An integer between 1 and 10 (10 indicates excellent privacy settings).
      - details: A list of strings describing each finding and overall risk.
    """
    try:
        # Send request with a DNT header to simulate a privacy-minded request.
        response = requests.get(url, timeout=10, headers={"DNT": "1"})
        resp_headers = response.headers
        html = response.text
    except Exception as e:
        return 1, [f"Error fetching page: {e}"]

    details = []
    deduction = 0

    # --- Referrer Policy Analysis ---
    ref_policy = resp_headers.get("Referrer-Policy")
    if ref_policy:
        details.append(f"Referrer-Policy header found: {ref_policy}")
        # Define sets of good, acceptable, and poor policy values.
        good_values = {"no-referrer", "strict-origin", "same-origin", "strict-origin-when-cross-origin"}
        acceptable_values = {"origin", "origin-when-cross-origin"}
        poor_values = {"no-referrer-when-downgrade", "unsafe-url"}

        policy_val = ref_policy.lower().strip()
        if policy_val in good_values:
            details.append("Excellent Referrer Policy for privacy.")
        elif policy_val in acceptable_values:
            details.append("Acceptable Referrer Policy; however, more privacy could be achieved.")
            deduction += 1
        elif policy_val in poor_values:
            details.append("Poor Referrer Policy detected; this may expose sensitive URL data.")
            deduction += 3
        else:
            details.append("Unrecognized Referrer Policy value; caution advised.")
            deduction += 2
    else:
        details.append("Referrer-Policy header is missing.")
        deduction += 4

    # --- DNT Analysis ---
    # While DNT is typically a request header, some sites include a meta tag indicating they honor DNT.
    soup = BeautifulSoup(html, "html.parser")
    meta_dnt = soup.find("meta", attrs={"name": "dnt"})
    if meta_dnt:
        content = meta_dnt.get("content", "").strip()
        details.append(f"DNT meta tag found with content: '{content}'")
        if content in {"1", "true"}:
            details.append("DNT meta tag indicates that the site claims to honor Do Not Track.")
        else:
            details.append("DNT meta tag present but the value is unclear; may not indicate full compliance.")
            deduction += 1
    else:
        details.append("No DNT meta tag found in HTML.")
        deduction += 2

    # --- Final Score Computation ---
    final_score = max(1, min(10, 10 - deduction))
    if final_score == 10:
        details.append("✅ Excellent privacy configuration for Referrer Policy and DNT.")
    elif final_score < 5:
        details.append("⚠️ High risk: Privacy settings for Referrer Policy and/or DNT are poor.")
    else:
        details.append("⚠️ Moderate risk: Some improvements recommended for privacy headers.")

    return final_score, details

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Passive Referrer Policy & DNT Header Analysis Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()
    score, details = analyze_referrer_dnt(args.url)
    print(f"Final Score: {score}/10")
    for line in details:
        print(line)
