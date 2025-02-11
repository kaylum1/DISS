// extension/security.js
document.addEventListener('DOMContentLoaded', function () {
    chrome.storage.local.get('lastScan', function (data) {
        const ul = document.getElementById('securityList');
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

            securityScans.forEach(function (scan) {
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
            ul.innerHTML = '<li>No security scan results available.</li>';
        }
    });

    document.getElementById('backBtn').addEventListener('click', function () {
        window.location.href = chrome.runtime.getURL('popup.html');
    });
});
