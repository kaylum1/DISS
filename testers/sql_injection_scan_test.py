import requests
import urllib.parse

def check_sql_injection(url):
    """
    Real SQL injection scan that assigns a security score from 1 to 10.

    DISCLAIMER: This code is for educational and authorized security testing purposes only.
    Unauthorized testing of websites without permission is illegal.

    How it works:
    - Checks if the URL contains query parameters.
    - Injects SQL payloads into each query parameter and sends a GET request.
    - Scans the response for common SQL error messages.
    - Assigns a security score based on the percentage of vulnerable parameters.
    """

    # Parse the URL
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    
    # If no query parameters, nothing to test for SQL injection
    if not query:
        return "SQL Injection Scan score: 10/10 (No query parameters to test for SQL injection)"
    
    # Define common SQL injection payloads
    injection_payloads = [
        "'", "\"",
        "' OR '1'='1", "\" OR \"1\"=\"1",
        "';--", "\";--",
        "' OR 1=1 --", "\" OR 1=1 --"
    ]
    
    # Common SQL error indicators in response bodies
    error_indicators = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "sqlstate",
        "odbc sql server driver",
        "syntax error"
    ]
    
    vulnerable_params = 0
    total_params = len(query)
    detected_payloads = {}

    # Iterate over each query parameter
    for param in query:
        original_values = query[param]
        for payload in injection_payloads:
            # Replace the parameter's value with the payload
            query[param] = [payload]
            # Rebuild the query string and URL
            new_query = urllib.parse.urlencode(query, doseq=True)
            test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            
            try:
                response = requests.get(test_url, timeout=5)
                content = response.text.lower()
                # Check if any error indicator appears in the response
                if any(err in content for err in error_indicators):
                    vulnerable_params += 1
                    if param not in detected_payloads:
                        detected_payloads[param] = []
                    detected_payloads[param].append(payload)
                    break  # Stop testing this parameter after detecting a vulnerability
            except Exception as e:
                continue  # Skip this payload on request failure

        # Restore original parameter values before testing the next parameter
        query[param] = original_values

    if vulnerable_params == 0:
        return "SQL Injection Scan score: 10/10 (No SQL injection vulnerabilities found)"
    
    # Calculate the fraction of vulnerable parameters
    fraction_vulnerable = vulnerable_params / total_params
    
    # Scale the score from 1 (highly insecure) to 10 (fully secure)
    if fraction_vulnerable == 1:
        final_score = 1  # All parameters vulnerable
    elif fraction_vulnerable >= 0.75:
        final_score = 2
    elif fraction_vulnerable >= 0.50:
        final_score = 4
    elif fraction_vulnerable >= 0.25:
        final_score = 7
    else:
        final_score = 9  # Very few parameters vulnerable

    # Generate details report
    details = [f"{param}: {', '.join(set(detected_payloads[param]))}" for param in detected_payloads]
    return f"SQL Injection Scan score: {final_score}/10 (Vulnerable parameters: {vulnerable_params}/{total_params}) - Detected Payloads: {'; '.join(details)}"


if __name__ == "__main__":
    test_url = "http://localhost:8000/vulnerable-sql"
    print(check_sql_injection(test_url))