import requests

def scan_url(url):
    """
    Checks HTTPS security and returns a score from 1 to 10 based on:
    - TLS version (4 points max)
    - Certificate validity (3 points max)
    - HSTS presence (3 points max)
    """
    try:
        response = requests.get(url, timeout=10)
        score = 0
        details = []

        # Check if HTTPS is used
        if not url.startswith("https://"):
            return "HTTPS Scan score: 1/10 (Website does not use HTTPS)"

        score += 2  # Base score for using HTTPS

        # Check TLS version (requires 'requests' with SSL details)
        try:
            tls_version = response.raw.version
            if tls_version == 3:  # TLS 1.2
                score += 3
                details.append("TLS 1.2 used")
            elif tls_version == 4:  # TLS 1.3
                score += 4
                details.append("TLS 1.3 used")
            else:
                details.append("Weak TLS version detected")
        except Exception as e:
            details.append(f"TLS check failed: {e}")

        # Check Certificate Validity
        cert_expiry = response.raw._connection.sock.getpeercert().get('notAfter', '')
        if cert_expiry:
            from datetime import datetime
            from dateutil import parser

            expiry_date = parser.parse(cert_expiry)
            days_remaining = (expiry_date - datetime.utcnow()).days

            if days_remaining > 180:
                score += 3
                details.append("Certificate validity > 180 days")
            elif 30 <= days_remaining <= 180:
                score += 2
                details.append("Certificate validity 30-180 days")
            elif 0 < days_remaining < 30:
                details.append("Certificate expiring soon (<30 days)")
            else:
                score -= 3
                details.append("Certificate expired!")
        else:
            details.append("Could not verify certificate validity")

        # Check for HSTS header
        if 'strict-transport-security' in response.headers:
            score += 3
            details.append("HSTS is enabled")
        else:
            details.append("No HSTS detected")

        # Clamp final score between 1 and 10
        score = max(1, min(10, score))
        return f"HTTPS Scan score: {score}/10 ({'; '.join(details)})"

    except Exception as e:
        return f"Error performing HTTPS scan: {str(e)}"
