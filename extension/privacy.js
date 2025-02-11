// extension/privacy.js
document.addEventListener('DOMContentLoaded', function () {
    chrome.storage.local.get('lastScan', function (data) {
        const ul = document.getElementById('privacyList');
        if (data.lastScan) {
            const privacyScans = [
                { name: data.lastScan.priv_scan1_name, result: data.lastScan.priv_scan1_result },
                { name: data.lastScan.priv_scan2_name, result: data.lastScan.priv_scan2_result },
                { name: data.lastScan.priv_scan3_name, result: data.lastScan.priv_scan3_result },
                { name: data.lastScan.priv_scan4_name, result: data.lastScan.priv_scan4_result },
                { name: data.lastScan.priv_scan5_name, result: data.lastScan.priv_scan5_result }
            ];

            privacyScans.forEach(function (scan) {
                const li = document.createElement('li');
                li.textContent = `${scan.name}: ${scan.result}`;

                // Extract numeric score from result (assumes format: "Scan Name score: X/10")
                let match = scan.result.match(/(\d+)\/10/);
                if (match) {
                    let score = parseInt(match[1]);
                    if (score <= 4) {
                        li.style.color = 'red'; // Highlight in red for low scores
                        li.style.fontWeight = 'bold';
                    }
                }
                ul.appendChild(li);
            });
        } else {
            ul.innerHTML = '<li>No privacy scan results available.</li>';
        }
    });

    document.getElementById('backBtn').addEventListener('click', function () {
        window.location.href = chrome.runtime.getURL('popup.html');
    });
});
