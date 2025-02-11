document.addEventListener('DOMContentLoaded', function() {
    chrome.storage.local.get('lastScan', function(data) {
      const ul = document.getElementById('privacyList');
      if (data.lastScan) {
        const privacyScans = [
          { name: data.lastScan.priv_scan1_name, result: data.lastScan.priv_scan1_result },
          { name: data.lastScan.priv_scan2_name, result: data.lastScan.priv_scan2_result },
          { name: data.lastScan.priv_scan3_name, result: data.lastScan.priv_scan3_result },
          { name: data.lastScan.priv_scan4_name, result: data.lastScan.priv_scan4_result },
          { name: data.lastScan.priv_scan5_name, result: data.lastScan.priv_scan5_result }
        ];
        privacyScans.forEach(function(scan) {
          const li = document.createElement('li');
          li.textContent = `${scan.name} = ${scan.result}`;
          ul.appendChild(li);
        });
      } else {
        ul.innerHTML = '<li>No privacy scan results available.</li>';
      }
    });
  });