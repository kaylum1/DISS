# server/Security_scans/crrf_scan.py

import requests
from bs4 import BeautifulSoup

def check_crrf(url):
    """
    Performs a basic CSRF (referred here as CRRF) scan on the provided URL.
    
    Method:
      - Fetch the page from the given URL.
      - Parse the HTML to find all <form> elements.
      - For each form, check for a hidden input whose name contains "csrf" (case-insensitive).
      
    Scoring:
      - If no forms are found, return a score of 10/10 (CSRF protection is not applicable).
      - Otherwise, compute the fraction of forms that include a CSRF token.
      - The final score is calculated as: final_score = round(1 + 9 * (protected_forms / total_forms))
        so that if all forms are protected, score is 10; if none are, score is 1.
    
    Returns:
      A string in the format:
      "CRRF Scan score: X/10 (Y out of Z forms are protected against CSRF)"
    """
    try:
        response = requests.get(url, timeout=10)
        html = response.text
        soup = BeautifulSoup(html, "html.parser")
        
        forms = soup.find_all("form")
        total_forms = len(forms)
        
        # If no forms are found, assume no CSRF risk
        if total_forms == 0:
            return "CRRF Scan score: 10/10 (No forms found; CSRF not applicable)"
        
        protected_forms = 0
        for form in forms:
            # Look for a hidden input with a name containing "csrf"
            hidden_inputs = form.find_all("input", {"type": "hidden"})
            csrf_found = any("csrf" in (inp.get("name") or "").lower() for inp in hidden_inputs)
            if csrf_found:
                protected_forms += 1
        
        fraction_protected = protected_forms / total_forms
        # Scale: if fraction_protected==1, then score is 10; if 0, score is 1.
        final_score = round(1 + 9 * fraction_protected)
        
        return (f"CRRF Scan score: {final_score}/10 "
                f"({protected_forms} out of {total_forms} forms are protected against CSRF)")
    
    except Exception as e:
        return f"Error performing CRRF scan: {str(e)}"


