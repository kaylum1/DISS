# server/Security_scans/Passive_Performance_and_Configuration_Analysis_Scanner.py
import requests
import argparse
import time
from urllib.parse import urlparse

# Score deduction values for misconfigurations
SCORE_DEDUCTIONS = {
    "no_http2": 2,
    "no_compression": 2,
    "weak_cache": 1,
    "no_keep_alive": 2,
    "redirects": 2,
    "large_page": 3,
    "excessive_requests": 2
}

def check_http_version(url):
    try:
        response = requests.get(url, timeout=10)
        if "http/2" in response.raw.version:
            return "HTTP/2"
        return "HTTP/1.1"
    except Exception:
        return "Unknown"

def check_compression(headers):
    content_encoding = headers.get("Content-Encoding", "")
    return "gzip" in content_encoding or "br" in content_encoding

def check_cache_control(headers):
    cache_control = headers.get("Cache-Control", "")
    return bool(cache_control) and any(val in cache_control.lower() for val in ["max-age", "public", "private"])

def check_keep_alive(headers):
    connection = headers.get("Connection", "").lower()
    return "keep-alive" in connection

def check_redirects(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        return len(response.history)
    except Exception:
        return 0

def check_page_size(url):
    try:
        response = requests.get(url, timeout=10)
        page_size = len(response.content) / 1024
        return round(page_size, 2)
    except Exception:
        return 0

def check_request_count(url):
    try:
        response = requests.get(url, timeout=10)
        return len(response.headers)
    except Exception:
        return 0

def analyze_performance(url):
    base_score = 10
    details = []

    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
    except requests.RequestException:
        return 1, ["❌ Could not analyze the webpage."]

    http_version = check_http_version(url)
    if http_version == "HTTP/2":
        details.append("✅ HTTP/2 is supported.")
    else:
        base_score -= SCORE_DEDUCTIONS["no_http2"]
        details.append("⚠️ HTTP/2 is not enabled (Consider upgrading).")

    if check_compression(headers):
        details.append("✅ Compression is enabled.")
    else:
        base_score -= SCORE_DEDUCTIONS["no_compression"]
        details.append("⚠️ Compression is not enabled (Consider enabling GZIP/Brotli).")

    if check_cache_control(headers):
        details.append("✅ Cache-Control headers are set.")
    else:
        base_score -= SCORE_DEDUCTIONS["weak_cache"]
        details.append("⚠️ Cache-Control headers are missing or weak.")

    if check_keep_alive(headers):
        details.append("✅ Keep-Alive is enabled.")
    else:
        base_score -= SCORE_DEDUCTIONS["no_keep_alive"]
        details.append("⚠️ Keep-Alive is not enabled.")

    redirects = check_redirects(url)
    if redirects > 1:
        base_score -= SCORE_DEDUCTIONS["redirects"]
        details.append(f"⚠️ {redirects} redirects detected.")
    else:
        details.append("✅ Minimal redirects detected.")

    page_size = check_page_size(url)
    if page_size > 2000:
        base_score -= SCORE_DEDUCTIONS["large_page"]
        details.append(f"⚠️ Page size is large ({page_size} KB).")
    else:
        details.append(f"✅ Page size is optimal ({page_size} KB).")

    request_count = check_request_count(url)
    if request_count > 100:
        base_score -= SCORE_DEDUCTIONS["excessive_requests"]
        details.append(f"⚠️ High number of HTTP requests ({request_count}).")
    else:
        details.append(f"✅ HTTP request count is optimal ({request_count}).")

    final_score = max(1, min(10, base_score))
    if final_score == 10:
        details.append("✅ Excellent performance and configuration.")
    elif final_score < 5:
        details.append("⚠️ Serious performance/security misconfigurations!")
    else:
        details.append("⚠️ Moderate performance/security risks.")

    return final_score, details

def get_base_url(url):
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def main():
    parser = argparse.ArgumentParser(description="Passive Performance & Configuration Analysis Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    base_url = get_base_url(args.url)
    print(f"🔍 Scanning performance & configuration for: {base_url}\n")
    score, details = analyze_performance(base_url)
    print("\n--- Performance & Configuration Report ---")
    for line in details:
        print(f" - {line}")
    print(f"\n--- Security Score ---\nSecurity Score: {score} / 10")
    if score < 5:
        print("⚠️ Serious performance/security misconfigurations!")
    elif score < 8:
        print("⚠️ Some optimization/security risks exist.")
    else:
        print("✅ Strong performance and configuration.")

if __name__ == "__main__":
    main()
