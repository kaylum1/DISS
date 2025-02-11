# server/Security_scans/ssl_tls_configuration_scan.py

import socket
import ssl
import datetime
from urllib.parse import urlparse

def check_ssl_tls_configuration(url):
    """
    Performs an SSL/TLS configuration scan on the given URL and returns a security score between 1 and 10.
    
    The score is based on:
      - TLS version negotiated:
          * TLSv1.3: 4 points
          * TLSv1.2: 3 points
          * TLSv1.1: 1 point
          * TLSv1.0 or older: 0 points
      - Certificate validity:
          * If the certificate is not expired: 3 points
          * Expired certificate: 0 points
    
    The total raw score (max 7) is then scaled to a 1–10 range.
    
    Returns a string with the score and details.
    
    DISCLAIMER: This script is for educational purposes only.
    """
    try:
        # Parse the URL
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port if parsed.port else 443

        # Create a default SSL context (which enforces secure settings)
        context = ssl.create_default_context()

        # Connect and perform SSL handshake
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_version = ssock.version()  # e.g. "TLSv1.2", "TLSv1.3"
                cert = ssock.getpeercert()

        # Determine TLS version score
        if tls_version == "TLSv1.3":
            tls_score = 4
        elif tls_version == "TLSv1.2":
            tls_score = 3
        elif tls_version == "TLSv1.1":
            tls_score = 1
        else:
            tls_score = 0

        # Check certificate validity: using the "notAfter" field from the certificate.
        # Example format: "Jun  1 12:00:00 2023 GMT"
        not_after = cert.get('notAfter')
        cert_expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        now = datetime.datetime.utcnow()
        cert_valid_score = 3 if cert_expiry > now else 0

        # Raw total score (maximum 7)
        raw_total = tls_score + cert_valid_score
        if raw_total < 1:
            raw_total = 1

        # Scale raw_total (max 7) to a 1-10 range.
        scaled_score = raw_total * (10 / 7)
        final_score = round(min(max(scaled_score, 1), 10))

        # Prepare details for the report
        details = (f"TLS Version: {tls_version}, "
                   f"Certificate Expiry: {cert_expiry.strftime('%Y-%m-%d')}")
        return f"SSL/TLS configuration score: {final_score} / 10 ({details})"

    except Exception as e:
        return f"Error performing SSL/TLS scan: {str(e)}"

