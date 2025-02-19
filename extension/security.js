document.addEventListener('DOMContentLoaded', function () {
    chrome.storage.local.get('lastScan', function (data) {
        const container = document.getElementById('securityList');
        if (data.lastScan) {
            const securityScans = [
                { name: data.lastScan.sec_scan1_name, result: data.lastScan.sec_scan1_result },
                { name: data.lastScan.sec_scan2_name, result: data.lastScan.sec_scan2_result },
                { name: data.lastScan.sec_scan3_name, result: data.lastScan.sec_scan3_result },
                { name: data.lastScan.sec_scan4_name, result: data.lastScan.sec_scan4_result },
                { name: data.lastScan.sec_scan5_name, result: data.lastScan.sec_scan5_result },
                { name: data.lastScan.sec_scan6_name, result: data.lastScan.sec_scan6_result },
                { name: data.lastScan.sec_scan7_name, result: data.lastScan.sec_scan7_result },
                { name: data.lastScan.sec_scan8_name, result: data.lastScan.sec_scan8_result },
                { name: data.lastScan.sec_scan9_name, result: data.lastScan.sec_scan9_result },
                { name: data.lastScan.sec_scan10_name, result: data.lastScan.sec_scan10_result }
            ];

            // Map specific scan names to their correct filenames
            const fileMap = {
                "HTTPS Scan": "httpscan.html",  // Ensure this links correctly
                "SQL Injection Scan": "sql_injection_scan.html",
                "Cross-Site Scripting Scan": "cross_site_scripting_scan.py",
                "Cookie Security Check": "Cookie_Security_Check.html",
                "SSL-TLS Configuration Scan": "ssl_tls_configuration_scan.html",
                "CSRF Scan": "crrf_scan.html",
                "Broken Authentication and Session Management Check": "broken_authentication_scan.html",
                "Directory Listing Check": "directory_listing_check_scan.html",
                "Open Redirect Check": "open_redirect_check_scan.html",
                "Security Headers Checker": "security_headers_checker.html"
            };

            const explanations = {
                "HTTPS Scan": "A low HTTPS score means the site is using outdated TLS versions or lacks HSTS, making it vulnerable to eavesdropping.",
                "SQL Injection Scan": "A low SQL injection score suggests that user inputs might be improperly sanitized, allowing attackers to manipulate database queries.",
                "Cross-Site Scripting Scan": "A low XSS score means the site does not properly escape user inputs, allowing attackers to inject malicious scripts.",
                "Cookie Security Check": "A low score here indicates cookies lack Secure, HttpOnly, or SameSite attributes, making them vulnerable to session hijacking.",
                "SSL-TLS Configuration Scan": "Weak SSL/TLS settings can expose sensitive data to man-in-the-middle attacks.",
                "CSRF Scan": "Missing CSRF tokens allow attackers to trick users into performing unintended actions on authenticated sites.",
                "Broken Authentication and Session Management Check": "Poor session management may allow attackers to hijack user accounts.",
                "Directory Listing Check": "If directory listing is enabled, attackers can browse internal files and potentially discover sensitive data.",
                "Open Redirect Check": "An open redirect allows attackers to redirect users to phishing or malicious sites."
            };

            securityScans.forEach(function (scan) {
                if (scan.name && scan.result) {
                    const scanItem = document.createElement('div');
                    scanItem.classList.add('scan-item');

                    const scanHeader = document.createElement('div');
                    scanHeader.textContent = scan.name;
                    scanHeader.classList.add('scan-header');

                    let match = scan.result.match(/(\d+)\/10/);
                    let scanDetails = document.createElement('div');
                    scanDetails.classList.add('scan-details', 'hidden');

                    // Add scan result text first
                    const resultText = document.createElement('p');
                    resultText.textContent = scan.result;
                    scanDetails.appendChild(resultText);

                    if (match) {
                        let score = parseInt(match[1]);
                        if (score <= 4) {
                            scanHeader.style.color = 'red';
                            scanHeader.style.fontWeight = 'bold';

                            let explanation = document.createElement('p');
                            explanation.classList.add('low-score-message');
                            explanation.textContent = explanations[scan.name] || "This issue may pose a security risk.";

                            scanDetails.appendChild(explanation);

                            // **ADD "MORE INFO" BUTTON BELOW EXPLANATION**
                            let moreInfoButton = document.createElement("button");
                            moreInfoButton.textContent = "More Info";
                            moreInfoButton.classList.add("more-info-btn");

                            // Open static HTML page in new tab with different URL for each scan type
                            // Correctly map scan name to file
                            let filename = fileMap[scan.name] || scan.name.replace(/ /g, "_") + ".html";
                            moreInfoButton.addEventListener("click", function () {
                                chrome.tabs.create({ url: chrome.runtime.getURL("info_pages/" + filename) });
                            });

                            scanDetails.appendChild(moreInfoButton);
                        }
                    }

                    scanHeader.addEventListener("click", function () {
                        scanDetails.classList.toggle("hidden");
                    });

                    scanItem.appendChild(scanHeader);
                    scanItem.appendChild(scanDetails);
                    container.appendChild(scanItem);
                }
            });
        } else {
            container.innerHTML = '<p>No security scan results available.</p>';
        }
    });

    document.getElementById('backBtn').addEventListener('click', function () {
        window.location.href = chrome.runtime.getURL('popup.html');
    });
});