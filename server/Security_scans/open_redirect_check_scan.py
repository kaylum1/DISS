# server/Security_scans/open_redirect_check_scan.py

import requests
import urllib.parse

def check_open_redirect(url):
    """
    Performs a basic open redirect scan on the provided URL.

    Method:
      - Parse the URL for query parameters.
      - Look for common redirection parameters such as "redirect", "url", "next", etc.
      - For each such parameter, replace its value with a payload (e.g., "http://evil.com")
        and send a GET request with redirects disabled.
      - If a redirect is issued and the Location header contains the payload,
        consider that parameter vulnerable.

    Scoring:
      - If no common redirection parameters are found, return 10/10.
      - Otherwise, calculate the fraction of vulnerable parameters.
      - Final score is computed as:
            final_score = max(1, round(10 * (1 - fraction_vulnerable)))
        so that if all tested parameters are vulnerable, the score is 1/10;
        if none are, the score is 10/10.

    Returns:
      A string in the format:
      "Open Redirect Check Scan score: X/10 (details...)"
    """
    try:
        parsed = urllib.parse.urlparse(url)
        query_dict = urllib.parse.parse_qs(parsed.query)
        
        # List of common redirection parameter names
        redir_params = ["redirect", "url", "next", "r", "dest"]
        
        total_tested = 0
        vulnerable_count = 0
        details_list = []
        
        # If no query parameters exist, assume the risk is low.
        if not query_dict:
            return "Open Redirect Check Scan score: 10/10 (No query parameters found)"
        
        for param, values in query_dict.items():
            if param.lower() in redir_params:
                total_tested += 1
                # Replace this parameter's value with the external payload
                query_dict[param] = ["http://evil.com"]
                new_query = urllib.parse.urlencode(query_dict, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment
                ))
                
                try:
                    response = requests.get(test_url, allow_redirects=False, timeout=10)
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("Location", "").lower()
                        if "evil.com" in location:
                            vulnerable_count += 1
                            details_list.append(f"Parameter '{param}' vulnerable")
                        else:
                            details_list.append(f"Parameter '{param}' appears safe")
                    else:
                        details_list.append(f"Parameter '{param}' did not trigger a redirect")
                except Exception as e:
                    details_list.append(f"Parameter '{param}' test error: {e}")
        
        # If no common redirection parameters were found among query parameters.
        if total_tested == 0:
            return "Open Redirect Check Scan score: 10/10 (No common redirection parameters found)"
        
        fraction_vulnerable = vulnerable_count / total_tested
        final_score = max(1, round(10 * (1 - fraction_vulnerable)))
        return f"Open Redirect Check Scan score: {final_score}/10 ({'; '.join(details_list)})"
    
    except Exception as e:
        return f"Error performing open redirect scan: {str(e)}"

