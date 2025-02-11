# server/Privacy_scan/third_party_data_collection_scan.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def check_third_party_data_collection(url):
    """
    Scans the website for third-party data collection indicators.
    
    Method:
      - Fetch the homepage HTML.
      - Parse for tags (e.g., script, link, img) with src/href attributes.
      - Count distinct external domains (domains not matching the site's domain).
    
    Scoring:
      - If no external domains are found: score 10.
      - Otherwise, score = max(1, 10 - number of distinct external domains).
    
    Returns:
      A string with the final score and details.
    """
    try:
        response = requests.get(url, timeout=10)
        html = response.text
        soup = BeautifulSoup(html, "html.parser")
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc.lower()
        
        external_domains = set()
        
        # Check tags with src attributes.
        for tag in soup.find_all(src=True):
            src = tag.get("src")
            parsed_src = urlparse(src)
            if parsed_src.netloc and base_domain not in parsed_src.netloc:
                external_domains.add(parsed_src.netloc.lower())
        
        # Check tags with href attributes.
        for tag in soup.find_all(href=True):
            href = tag.get("href")
            parsed_href = urlparse(href)
            if parsed_href.netloc and base_domain not in parsed_href.netloc:
                external_domains.add(parsed_href.netloc.lower())
        
        count = len(external_domains)
        score = max(1, 10 - count)
        details = f"Found external domains: {', '.join(external_domains)}" if count > 0 else "No external third-party domains detected."
        return f"Third-Party Data Collection Scan score: {score}/10 ({details})"
    except Exception as e:
        return f"Error in Third-Party Data Collection Scan: {str(e)}"

# For testing:
#if __name__ == "__main__":
#    test_url = "https://www.example.com/"
#    print(check_third_party_data_collection(test_url))
