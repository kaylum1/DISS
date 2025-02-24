import requests
import re
from urllib.parse import urlparse

# Define headers that are known to potentially leak sensitive data along with deduction points.
LEAKAGE_HEADERS = {
    "Server": 2,
    "X-Powered-By": 2,
    "X-AspNet-Version": 2,
    "X-AspNetMvc-Version": 2,
    "X-Backend-Server": 2,
    "Via": 1,
    "Forwarded": 2,
    "X-Forwarded-For": 2,
    "X-Real-IP": 1
}

# Regex to detect private/internal IP addresses.
PRIVATE_IP_REGEX = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
)

def analyze_data_leakage_headers(url):
    """
    Passively scans the HTTP headers of a webpage for data leakage.

    It checks for headers that may reveal sensitive internal details (such as "Server", "X-Powered-By",
    and proxy-related headers) and looks for private IP addresses within those header values.

    Returns:
      (final_score, details)
      
      - final_score: An integer between 1 and 10 (10 indicates minimal leakage).
      - details: A list of strings describing each finding.
    """
    try:
        response = requests.get(url, timeout=10)
    except Exception as e:
        return 1, [f"Error fetching page: {str(e)}"]

    details = []
    total_deduction = 0

    headers = response.headers

    for header, deduction in LEAKAGE_HEADERS.items():
        if header in headers:
            value = headers[header]
            details.append(f"Header '{header}' found with value: '{value}' (deduction {deduction})")
            total_deduction += deduction

            # Check for internal/private IP addresses in the header value.
            if PRIVATE_IP_REGEX.search(value):
                details.append(f"Header '{header}' reveals a private IP address (additional deduction 2)")
                total_deduction += 2

    final_score = max(1, min(10, 10 - total_deduction))
    if final_score == 10:
        details.append("✅ No significant data leakage detected in HTTP headers.")
    elif final_score < 5:
        details.append("⚠️ High risk: Several headers reveal potentially sensitive internal information.")
    else:
        details.append("⚠️ Moderate risk: Some HTTP headers may be leaking internal details.")

    return final_score, details

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Passive Data Leakage in HTTP Headers Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()
    score, details = analyze_data_leakage_headers(args.url)
    print(f"Final Score: {score}/10")
    for line in details:
        print(line)
