# server/score_calculator.py
import re

def calculate_final_score(*scan_results):
    """
    Extracts a numeric score from each scan result string (expected in the format '... score: X/10 ...'),
    computes the arithmetic average, and returns a final score (rounded to one decimal).
    
    If no valid scores are found, returns 0.
    """
    scores = []
    for result in scan_results:
        # Look for a pattern like "score: X/10" (case-insensitive)
        match = re.search(r'(\d+(?:\.\d+)?)/10', result, re.IGNORECASE)
        if match:
            try:
                score = float(match.group(1))
                scores.append(score)
            except ValueError:
                continue
    if scores:
        average = sum(scores) / len(scores)
        return round(average, 1)
    else:
        return 0
'''
# For quick testing:
if __name__ == "__main__":
    # Example scan strings:
    s1 = "HTTPS Scan score: 10/10 (Secure)"
    s2 = "Security Headers score: 8/10 (HSTS present; CSP missing)"
    s3 = "Cookie Security Check score: 9/10 (Cookies are Secure)"
    s4 = "XSS Scan score: 7/10 (No vulnerabilities)"
    s5 = "SQL Injection Scan score: 6/10 (No SQL injection vulnerabilities found)"
    # ... etc.
    final = calculate_final_score(s1, s2, s3, s4, s5)
    print("Final score:", final)
'''