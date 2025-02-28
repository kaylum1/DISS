/*
//extension/popup.js
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

*/







/*
function updatePopup() {
  chrome.storage.local.get(['activeTab', 'lastScan'], function(data) {
    const activeTabUrl = data.activeTab;
    const scanData = data.lastScan;
    const urlText = document.getElementById('urlText');
    const scoreCircle = document.getElementById('scoreCircle');
    const spinner = document.getElementById('spinner');
    const scoreText = document.getElementById('scoreText');
    
    // Update the URL display
    if (activeTabUrl) {
      urlText.textContent = `URL: ${activeTabUrl}`;
    } else {
      urlText.textContent = "URL: Not available";
    }
    
    // Update score display based on scan data
    if (scanData && scanData.url === activeTabUrl && scanData.final_score !== undefined) {
      const finalScore = scanData.final_score;
      scoreText.textContent = finalScore;
      scoreText.style.display = 'block';
      spinner.style.display = 'none';

      // Set the circle color based on the final score
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
      // No scan data yet; show spinner.
      scoreText.textContent = '';
      scoreText.style.display = 'none';
      spinner.style.display = 'block';
      scoreCircle.style.backgroundColor = '#ccc';
    }
  });
}

document.addEventListener('DOMContentLoaded', updatePopup);

// Listen for storage changes (activeTab or lastScan) to update the UI.
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

// Gear button: Navigate to settings page.
document.getElementById('settingsBtn').addEventListener('click', function () {
  window.location.href = 'settings.html';
});



document.getElementById('logsPage').addEventListener('click', function () {
  window.open('http://localhost:8000/logs', '_blank');
});
*/




// extension/popup.js

function updatePopup() {
  chrome.storage.local.get(['activeTab', 'lastScan'], function(data) {
    const activeTabUrl = data.activeTab;
    const scanData = data.lastScan;
    const urlText = document.getElementById('urlText');
    const scoreCircle = document.getElementById('scoreCircle');
    const spinner = document.getElementById('spinner');
    const scoreText = document.getElementById('scoreText');
    const statusMessageElement = document.getElementById('statusMessage');

    // Update the URL display.
    if (activeTabUrl) {
      urlText.textContent = `URL: ${activeTabUrl}`;
    } else {
      urlText.textContent = "URL: Not available";
    }

    // Update score display based on scan data.
    if (scanData && scanData.url === activeTabUrl && scanData.final_score !== undefined) {
      const finalScore = scanData.final_score;
      scoreText.textContent = finalScore;
      scoreText.style.display = 'block';
      spinner.style.display = 'none';

      // Set the circle color based on the final score.
      let bgColor;
      if (finalScore >= 8) {
        bgColor = '#4CAF50'; // green
      } else if (finalScore >= 5) {
        bgColor = '#FFC107'; // amber
      } else {
        bgColor = '#F44336'; // red
      }
      scoreCircle.style.backgroundColor = bgColor;

      // Update the status message based on the score change.
      let statusText = scanData.scoreStatus || "nothing changed";
      let statusColor = '#ccc'; // default neutral color
      if (statusText === "better score") {
        statusColor = '#4CAF50'; // green for improvement
      } else if (statusText === "worse score") {
        statusColor = '#F44336'; // red for decline
      }
      statusMessageElement.textContent = statusText;
      statusMessageElement.style.backgroundColor = statusColor;
      statusMessageElement.style.display = 'block';
    } else {
      // No scan data yet; show spinner and default status.
      scoreText.textContent = '';
      scoreText.style.display = 'none';
      spinner.style.display = 'block';
      scoreCircle.style.backgroundColor = '#ccc';
      statusMessageElement.textContent = "nothing changed";
      statusMessageElement.style.backgroundColor = '#ccc';
      statusMessageElement.style.display = 'block';
    }
  });
}

document.addEventListener('DOMContentLoaded', updatePopup);

// Listen for storage changes (activeTab or lastScan) to update the UI.
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

// Gear button: Navigate to settings page.
document.getElementById('settingsBtn').addEventListener('click', function () {
  window.location.href = 'settings.html';
});

document.getElementById('logsPage').addEventListener('click', function () {
  window.open('http://localhost:8000/logs', '_blank');
});
