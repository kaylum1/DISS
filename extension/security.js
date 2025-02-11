document.addEventListener('DOMContentLoaded', function() {
    chrome.storage.local.get('lastScan', function(data) {
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
        securityScans.forEach(function(scan) {
          const li = document.createElement('li');
          li.textContent = `${scan.name} = ${scan.result}`;
          ul.appendChild(li);
        });
      } else {
        ul.innerHTML = '<li>No security scan results available.</li>';
      }
    });
  });