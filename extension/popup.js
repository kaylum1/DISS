/*
// extension/popup.js
document.addEventListener('DOMContentLoaded', function () {
    chrome.storage.local.get('lastScan', function (data) {
      const resultDiv = document.getElementById('result');
      if (data.lastScan) {
        const s = data.lastScan;
        let text = `URL: ${s.url}\n\n`;
        text += "Security Scans:\n";
        text += `${s.sec_scan1_name} = ${s.sec_scan1_result}\n`;
        text += `${s.sec_scan2_name} = ${s.sec_scan2_result}\n`;
        text += `${s.sec_scan3_name} = ${s.sec_scan3_result}\n`;
        text += `${s.sec_scan4_name} = ${s.sec_scan4_result}\n`;
        text += `${s.sec_scan5_name} = ${s.sec_scan5_result}\n`;
        text += `${s.sec_scan6_name} = ${s.sec_scan6_result}\n`;
        text += `${s.sec_scan7_name} = ${s.sec_scan7_result}\n`;
        text += `${s.sec_scan8_name} = ${s.sec_scan8_result}\n`;
        text += `${s.sec_scan9_name} = ${s.sec_scan9_result}\n`;
        text += `${s.sec_scan10_name} = ${s.sec_scan10_result}\n\n`;
        text += "Privacy Scans:\n";
        text += `${s.priv_scan1_name} = ${s.priv_scan1_result}\n`;
        text += `${s.priv_scan2_name} = ${s.priv_scan2_result}\n`;
        text += `${s.priv_scan3_name} = ${s.priv_scan3_result}\n`;
        text += `${s.priv_scan4_name} = ${s.priv_scan4_result}\n`;
        text += `${s.priv_scan5_name} = ${s.priv_scan5_result}\n\n`;
        text += `Final Score: ${s.final_score}/10`;
        resultDiv.textContent = text;
      } else {
        resultDiv.textContent = 'No scan result available.';
      }
    });
  });
*/

  // extension/popup.js
document.addEventListener('DOMContentLoaded', function () {
    chrome.storage.local.get('lastScan', function (data) {
      const scoreCircle = document.getElementById('scoreCircle');
      if (data.lastScan && data.lastScan.final_score !== undefined) {
        const finalScore = data.lastScan.final_score;
        scoreCircle.textContent = finalScore;
        // Set circle color based on score:
        // Score >= 8: green; 5-7: amber; below 5: red.
        let bgColor;
        if (finalScore >= 8) {
          bgColor = '#4CAF50'; // green
        } else if (finalScore >= 5) {
          bgColor = '#FFC107'; // amber
        } else {
          bgColor = '#F44336'; // red
        }
        scoreCircle.style.backgroundColor = bgColor;
      } else {
        scoreCircle.textContent = '--';
      }
    });
  
    // Navigate to the detailed pages on button clicks.
    document.getElementById('securityBtn').addEventListener('click', function () {
      window.location.href = 'security.html';
    });
  
    document.getElementById('privacyBtn').addEventListener('click', function () {
      window.location.href = 'privacy.html';
    });
  });
  
  
  