# server/Security_scans/cross_site_scripting_scan.py
import requests
import urllib.parse

def check_cross_site_scripting(url):
    """
    Performs a basic XSS scan on the provided URL.

    Method:
      1. Parse the URL for query parameters.
      2. If no query parameters exist, return a score of 10/10.
      3. For each parameter, replace its value with a unique payload.
      4. Fetch the modified URL and check whether the payload appears unmodified in the response.
      5. Compute the fraction of parameters that appear vulnerable.
      6. Calculate the final score as:
             final_score = max(1, round(10 * (1 - fraction_vulnerable)))
         (i.e. if no parameter reflects the payload, score is 10; if all do, score is 1.)
    
    Returns:
      A string in the format:
      "Cross-Site Scripting Scan score: X/10 (details...)"
    """
    try:
        parsed = urllib.parse.urlparse(url)
        query_dict = urllib.parse.parse_qs(parsed.query)
        
        # If no query parameters exist, nothing to test
        if not query_dict:
            return "Cross-Site Scripting Scan score: 10/10 (No query parameters to test for XSS)"
        
        # Define a unique payload to inject
        payload = "XSS_PAYLOAD_12345"
        vulnerable_count = 0
        total_params = len(query_dict)
        details_list = []
        
        # Iterate over each query parameter
        for param in query_dict:
            # Backup original values for restoration
            original_values = query_dict[param]
            # Replace the parameter's values with the payload
            query_dict[param] = [payload]
            # Rebuild the query string with the payload injected
            new_query = urllib.parse.urlencode(query_dict, doseq=True)
            # Rebuild the test URL with the new query string
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment
            ))
            
            try:
                response = requests.get(test_url, timeout=10)
                # Check if the payload appears in the response (unmodified)
                if payload in response.text:
                    vulnerable_count += 1
                    details_list.append(f"Parameter '{param}' appears vulnerable")
                else:
                    details_list.append(f"Parameter '{param}' appears secure")
            except Exception as req_e:
                details_list.append(f"Parameter '{param}' test error: {req_e}")
            
            # Restore original value before moving to the next parameter
            query_dict[param] = original_values
        
        fraction_vulnerable = vulnerable_count / total_params
        final_score = max(1, round(10 * (1 - fraction_vulnerable)))
        return f"Cross-Site Scripting Scan score: {final_score}/10 ({'; '.join(details_list)})"
    
    except Exception as e:
        return f"Error performing cross-site scripting scan: {str(e)}"



import requests
from bs4 import BeautifulSoup

def find_and_test_forms(url, payload="XSS_PAYLOAD_12345"):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    results = []
    
    for form in forms:
        form_details = {}
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        data = {}
        
        for input_tag in inputs:
            name = input_tag.get('name')
            input_type = input_tag.get('type', 'text')
            # Inject payload for text-like inputs
            if name:
                if input_type in ['text', 'search', 'email']:
                    data[name] = payload
                else:
                    data[name] = input_tag.get('value', '')
        
        target_url = action if action.startswith('http') else urllib.parse.urljoin(url, action)
        
        try:
            if method == 'post':
                form_response = requests.post(target_url, data=data, timeout=10)
            else:
                form_response = requests.get(target_url, params=data, timeout=10)
            
            if payload in form_response.text:
                form_details['result'] = f"Form at {target_url} appears vulnerable"
            else:
                form_details['result'] = f"Form at {target_url} appears secure"
        except Exception as e:
            form_details['result'] = f"Error testing form at {target_url}: {e}"
        
        results.append(form_details['result'])
    
    return results

# Example usage:
url_to_test = "https://httpbin.org/get?test=123"
print(find_and_test_forms(url_to_test))
print("\n")
print(check_cross_site_scripting(url_to_test))

