import requests
import argparse
from urllib.parse import urljoin

# Common directories that should not be publicly accessible
SENSITIVE_DIRECTORIES = [
    "backup", "logs", "admin", "config", "private", "database", "server-status"
]

# File types that indicate potential security risks
EXPOSED_FILE_TYPES = [
    ".log", ".sql", ".bak", ".env", ".xml", ".conf", ".json", ".yml", ".ini"
]

# Score deductions based on security risk
SCORE_DEDUCTIONS = {
    "open_directory": 3,
    "exposed_sensitive_files": 4,
    "exposed_backup_files": 5,
}

def check_directory_listing(url):
    """
    Checks if a directory listing is enabled by attempting to access known directories.
    """
    open_directories = []
    exposed_files = []
    
    for directory in SENSITIVE_DIRECTORIES:
        check_url = urljoin(url, f"{directory}/")
        try:
            response = requests.get(check_url, timeout=5)
            if response.status_code == 200 and "Index of" in response.text:
                open_directories.append(check_url)

                # Check for exposed files in the directory listing
                for file_type in EXPOSED_FILE_TYPES:
                    if file_type in response.text:
                        exposed_files.append(file_type)
        except requests.RequestException:
            continue  # Skip if request fails

    return open_directories, exposed_files

def analyze_directory_security(url):
    """
    Performs directory listing analysis and assigns a security score.
    """
    base_score = 10
    details = []

    # Check for open directories
    open_directories, exposed_files = check_directory_listing(url)

    if open_directories:
        base_score -= SCORE_DEDUCTIONS["open_directory"]
        details.append(f"❌ Open directories detected: {', '.join(open_directories[:3])}... (Score -{SCORE_DEDUCTIONS['open_directory']})")

    if exposed_files:
        base_score -= SCORE_DEDUCTIONS["exposed_sensitive_files"]
        details.append(f"⚠️ Exposed sensitive files detected: {', '.join(set(exposed_files))} (Score -{SCORE_DEDUCTIONS['exposed_sensitive_files']})")

    # Ensure score stays within 1-10 range
    final_score = max(1, min(10, base_score))

    if final_score == 10:
        details.append("✅ No directory listing vulnerabilities detected.")
    elif final_score < 5:
        details.append("⚠️ High risk: The website exposes sensitive directories and files!")
    else:
        details.append("⚠️ Moderate risk: Some directories are publicly accessible.")

    return final_score, details

def main():
    parser = argparse.ArgumentParser(description="Passive Directory Listing Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target website URL")
    args = parser.parse_args()

    print(f"🔍 Scanning for open directories on: {args.url}\n")

    score, details = analyze_directory_security(args.url)

    print("\n--- 🔍 Directory Listing Security Report ---")
    for line in details:
        print(f" - {line}")

    print("\n--- 🔢 Security Score ---")
    print(f"Security Score: {score} / 10")
    if score < 5:
        print("⚠️ The website has serious directory listing security risks!")
    elif score < 8:
        print("⚠️ The website has some exposed directories. Fixing recommended.")
    else:
        print("✅ The website does not expose any open directories.")

if __name__ == "__main__":
    main()
