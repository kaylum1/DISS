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
