

function updatePopup() {
    chrome.storage.local.get(['activeTab', 'lastScan'], function(data) {
      const activeTabUrl = data.activeTab;
      const scanData = data.lastScan;
      const urlText = document.getElementById('urlText');
      const scoreCircle = document.getElementById('scoreCircle');
      const spinner = document.getElementById('spinner');
      const scoreText = document.getElementById('scoreText');
      
      // Update URL display with the active tab's URL.
      if (activeTabUrl) {
        urlText.textContent = `URL: ${activeTabUrl}`;
      } else {
        urlText.textContent = "URL: Not available";
      }
      
      // Check if scan data is available for the active tab.
      if (scanData && scanData.url === activeTabUrl && scanData.final_score !== undefined) {
        const finalScore = scanData.final_score;
        scoreText.textContent = finalScore;
        scoreText.style.display = 'block';
        spinner.style.display = 'none';
  
        // Set the circle color based on the score.
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
        // No scan data: show spinner.
        scoreText.textContent = '';
        scoreText.style.display = 'none';
        spinner.style.display = 'block';
        scoreCircle.style.backgroundColor = '#ccc';
      }
    });
  }
  
  document.addEventListener('DOMContentLoaded', updatePopup);
  
  // Listen for changes to update the popup UI when activeTab or lastScan changes.
  chrome.storage.onChanged.addListener(function(changes, area) {
    if (area === 'local' && (changes.activeTab || changes.lastScan)) {
      updatePopup();
    }
  });
  
  // Navigation buttons.
  document.getElementById('securityBtn').addEventListener('click', function () {
    window.location.href = 'security.html';
  });
  
  document.getElementById('privacyBtn').addEventListener('click', function () {
    window.location.href = 'privacy.html';
  });