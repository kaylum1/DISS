import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

# Score deduction values for different resource types.
SCORE_DEDUCTIONS = {
    "scripts": 3,
    "stylesheets": 2,
    "iframes": 3,
    "images": 1,
    "other": 1
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

def detect_mixed_content(url, html):
    """
    Scans the webpage for mixed content (HTTP resources on an HTTPS page).
    Returns a dictionary categorizing insecure resources.
    """
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    soup = BeautifulSoup(html, "html.parser")
    
    mixed_content = {
        "scripts": [],
        "stylesheets": [],
        "iframes": [],
        "images": [],
        "other": []
    }

    # Search for elements with src or href attributes.
    for tag in soup.find_all(["script", "link", "iframe", "img", "audio", "video", "source"]):
        src = tag.get("src") or tag.get("href")
        if src:
            absolute_url = urljoin(base_url, src)
            if absolute_url.startswith("http://"):  # Insecure HTTP resource on an HTTPS page.
                if tag.name == "script":
                    mixed_content["scripts"].append(absolute_url)
                elif tag.name == "link":
                    mixed_content["stylesheets"].append(absolute_url)
                elif tag.name == "iframe":
                    mixed_content["iframes"].append(absolute_url)
                elif tag.name == "img":
                    mixed_content["images"].append(absolute_url)
                else:
                    mixed_content["other"].append(absolute_url)
    return mixed_content

def calculate_score(mixed_content):
    """
    Assigns a security score (1-10) based on mixed content severity.
    Returns a tuple: (final_score, details_list)
    """
    base_score = 10
    total_deduction = 0
    details = []

    for category, urls in mixed_content.items():
        count = len(urls)
        if count > 0:
            deduction = min(count * SCORE_DEDUCTIONS[category], 5)  # Cap deduction per category.
            total_deduction += deduction
            details.append(f"❌ {count} insecure {category} detected (Score -{deduction})")
            for url in urls[:3]:  # Show up to 3 examples per category.
                details.append(f"   - {url}")

    final_score = max(1, base_score - total_deduction)
    if final_score == 10:
        details.append("✅ No mixed content detected. The site is secure.")
    elif final_score < 5:
        details.append("⚠️ High risk: The site has significant mixed content issues.")
    else:
        details.append("⚠️ Moderate risk: Some mixed content found. Consider fixing.")
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
    parser = argparse.ArgumentParser(description="Passive Mixed Content Detection Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    base_url = get_base_url(args.url)
    print(f"🔍 Scanning for mixed content on: {base_url}\n")

    html = get_page_content(base_url)
    if not html:
        print("❌ Failed to retrieve page content.")
        return

    mixed_content = detect_mixed_content(base_url, html)
    score, details = calculate_score(mixed_content)

    print("\n--- 🔍 Mixed Content Report ---")
    for line in details:
        print(f" - {line}")

    print("\n--- 🔢 Security Score ---")
    print(f"Security Score: {score} / 10")
    if score < 5:
        print("⚠️ The website has serious mixed content security issues!")
    elif score < 8:
        print("⚠️ The website has some mixed content risks. Fixing recommended.")
    else:
        print("✅ The website appears free from mixed content vulnerabilities.")

if __name__ == "__main__":
    main()

# Wrapper function for integration.
def analyze_mixed_content(url):
    """
    Wrapper function that analyzes mixed content for the given URL.
    Returns a tuple: (final_score, details)
    """
    html = get_page_content(url)
    if not html:
        return 1, ["❌ Could not retrieve page content."]
    mixed_content = detect_mixed_content(url, html)
    score, details = calculate_score(mixed_content)
    return score, details
