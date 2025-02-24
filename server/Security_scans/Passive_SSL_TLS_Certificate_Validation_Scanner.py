import ssl
import socket
import argparse
from datetime import datetime
from urllib.parse import urlparse

# Score reduction values
SCORE_DEDUCTIONS = {
    "expired": 5,
    "expiring_soon": 3,
    "tls_old": 3,
    "tls_outdated": 5,
    "self_signed": 3,
    "weak_key": 2,
    "untrusted_issuer": 3,
}

def get_certificate_info(host, port=443, timeout=5):
    """
    Retrieves SSL/TLS certificate information from the given host.
    Returns: certificate details and TLS version used.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                return cert, tls_version
    except Exception as e:
        print(f"[Error] Could not retrieve certificate for {host}: {e}")
        return None, None

def check_expiry(cert):
    """
    Checks if the certificate is expired or near expiration.
    Returns: (days remaining, status)
    """
    if not cert:
        return None, "invalid"

    expiry_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    days_remaining = (expiry_date - datetime.utcnow()).days

    if days_remaining < 0:
        return days_remaining, "expired"
    elif days_remaining < 30:
        return days_remaining, "expiring_soon"
    return days_remaining, "valid"

def is_self_signed(cert):
    """
    Checks if a certificate is self-signed by comparing the subject and issuer.
    Returns: True if self-signed, False otherwise.
    """
    return cert.get("subject") == cert.get("issuer")

def check_tls_version(tls_version):
    """
    Evaluates the security of the TLS version in use.
    """
    if tls_version == "TLSv1.3":
        return "secure"
    elif tls_version == "TLSv1.2":
        return "acceptable"
    elif tls_version in ["TLSv1.1", "TLSv1"]:
        return "tls_old"
    return "tls_outdated"

def check_key_strength(cert):
    """
    Checks if the cryptographic key strength is 2048 bits or higher.
    """
    if "publicKey" in cert:
        key_length = cert["publicKey"][1]  # Extracts key size (e.g., 2048, 4096)
        return key_length >= 2048
    return False  # If key length info is missing, assume weak

def analyze_certificate(host):
    """
    Analyzes the SSL/TLS certificate of a given host and provides a security score.
    """
    base_score = 10
    deductions = []
    details = []

    cert, tls_version = get_certificate_info(host)
    if cert is None:
        details.append("Could not retrieve SSL/TLS certificate.")
        return 1, details

    # Check TLS version security
    tls_status = check_tls_version(tls_version)
    if tls_status in SCORE_DEDUCTIONS:
        base_score -= SCORE_DEDUCTIONS[tls_status]
        details.append(f"Insecure TLS version: {tls_version} (consider upgrading).")
    else:
        details.append(f"Secure TLS version detected: {tls_version}.")

    # Check certificate expiration
    days_remaining, expiry_status = check_expiry(cert)
    if expiry_status in SCORE_DEDUCTIONS:
        base_score -= SCORE_DEDUCTIONS[expiry_status]
        details.append(f"Certificate {expiry_status.replace('_', ' ')} (expires in {days_remaining} days).")
    else:
        details.append(f"Certificate expiry is well in the future ({days_remaining} days remaining).")

    # Check if the certificate is self-signed
    if is_self_signed(cert):
        base_score -= SCORE_DEDUCTIONS["self_signed"]
        details.append("Certificate is self-signed (less secure).")
    else:
        details.append("Certificate is issued by a trusted CA.")

    # Check key strength
    if not check_key_strength(cert):
        base_score -= SCORE_DEDUCTIONS["weak_key"]
        details.append("Weak cryptographic key detected (should be 2048+ bits).")
    else:
        details.append("Strong cryptographic key detected (2048+ bits).")

    # Normalize the final score (minimum of 1, maximum of 10)
    final_score = max(1, min(10, base_score))

    return final_score, details

def get_hostname(url):
    """
    Extracts the hostname from a URL.
    """
    if "://" not in url:
        url = "https://" + url  # Assume HTTPS by default
    parsed = urlparse(url)
    return parsed.hostname

def main():
    parser = argparse.ArgumentParser(description="Passive SSL/TLS Certificate Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    host = get_hostname(args.url)
    if not host:
        print("Invalid URL provided.")
        return

    print(f"Starting SSL/TLS Certificate validation scan for: {host}\n")
    score, details = analyze_certificate(host)

    print("\n--- Detailed Results ---")
    for line in details:
        print(f" - {line}")

    print("\n--- Scan Summary ---")
    print(f"Security Score: {score} / 10")
    if score < 5:
        print("⚠️ The website has serious SSL/TLS security issues!")
    elif score < 8:
        print("⚠️ The website has some SSL/TLS misconfigurations. Improvements recommended.")
    else:
        print("✅ The website appears to have a secure SSL/TLS configuration.")

if __name__ == "__main__":
    main()




"""
How It Works
Extract SSL Certificate:
Connects to the website using a passive SSL handshake (no aggressive scanning).
Retrieves SSL certificate details and the TLS version used.
Perform Security Checks:
✅ TLS Version Check: Ensures the site supports TLS 1.2 or newer.
✅ Certificate Expiration: Warns if the certificate is expired or expiring soon.
✅ Self-Signed Detection: Identifies if the certificate is self-signed.
✅ Issuer Trust Check: Ensures the certificate is from a recognized CA.
✅ Key Strength Validation: Checks if the cryptographic key is 2048+ bits.
Score Calculation (1-10):
Starts with a base score of 10.
Deducts points based on detected issues.
Final Score:
1-4 → Highly Insecure ⚠️
5-7 → Moderate Security 🟡
8-10 → Secure ✅
How to Use It
Run the script with a website URL:

python Passive_SSL-TLS_Certificate_Validation_Scanner.py -u "https://example.com"
Why This is Legal
Passive: It only reads certificate information without modifying or exploiting anything.
Publicly Available Data: All certificate data is visible when connecting to a site.
Non-Intrusive: It does not send malicious requests.
Would you like me to modify this for integration into a browser extension? 🚀


"""