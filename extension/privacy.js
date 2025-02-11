// extension/privacy.js
document.addEventListener('DOMContentLoaded', function () {
    chrome.storage.local.get('lastScan', function (data) {
        const container = document.getElementById('privacyList');
        if (data.lastScan) {
            const privacyScans = [
                { name: data.lastScan.priv_scan1_name, result: data.lastScan.priv_scan1_result },
                { name: data.lastScan.priv_scan2_name, result: data.lastScan.priv_scan2_result },
                { name: data.lastScan.priv_scan3_name, result: data.lastScan.priv_scan3_result },
                { name: data.lastScan.priv_scan4_name, result: data.lastScan.priv_scan4_result },
                { name: data.lastScan.priv_scan5_name, result: data.lastScan.priv_scan5_result }
            ];

            const explanations = {
                "Tracker Detection": "A high number of trackers means the website collects and shares user data extensively.",
                "Fingerprinting Risk": "A high fingerprinting risk means the site can uniquely identify users across sessions, reducing anonymity.",
                "Data Leakage Check": "A low score indicates that personal information may be exposed in URLs or network requests.",
                "Privacy Policy Analysis": "A low score means the site's privacy policy lacks important details on data collection and third-party sharing.",
                "User Data Retention Check": "A poor retention score means the site stores user data longer than necessary, increasing privacy risks."
            };

            privacyScans.forEach(function (scan) {
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
                            explanation.textContent = explanations[scan.name] || "This issue may pose a privacy risk.";

                            scanDetails.appendChild(explanation); // Append explanation **after** result text
                        }
                    }

                    scanHeader.addEventListener('click', function () {
                        scanDetails.classList.toggle('hidden');
                    });

                    scanItem.appendChild(scanHeader);
                    scanItem.appendChild(scanDetails);
                    container.appendChild(scanItem);
                }
            });
        } else {
            container.innerHTML = '<p>No privacy scan results available.</p>';
        }
    });

    document.getElementById('backBtn').addEventListener('click', function () {
        window.location.href = chrome.runtime.getURL('popup.html');
    });
});
