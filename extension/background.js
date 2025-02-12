// extension/background.js


chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && (tab.url.startsWith('http://') || tab.url.startsWith('https://'))) {
      fetch('http://localhost:8000/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tab.url })
      })
      .then(response => response.json())
      .then(data => {
        console.log('Logged URL:', data);
        // Save the latest scan results for the popup
        chrome.storage.local.set({ lastScan: data });
      })
      .catch(error => {
        console.error('Error logging URL:', error);
      });
    }
  });


/*
// extension/background.js

// Function to log the URL to the backend and store scan results
function logUrl(url, retryCount = 3) {
    fetch('http://localhost:8000/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        console.log('Logged URL:', data);

        // Ensure sequential storage updates
        chrome.storage.local.set({ lastScan: data }, () => {
            if (chrome.runtime.lastError) {
                console.error('Storage Error:', chrome.runtime.lastError);
            } else {
                console.log('Scan results updated successfully');
            }
        });
    })
    .catch(error => {
        console.error('Error logging URL:', error);
        if (retryCount > 0) {
            console.log(`Retrying... (${3 - retryCount + 1})`);
            setTimeout(() => logUrl(url, retryCount - 1), 2000); // Retry after 2 seconds
        }
    });
}

// Listener to detect when a tab is updated (good for standard navigation)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && (tab.url.startsWith('http://') || tab.url.startsWith('https://'))) {
        logUrl(tab.url);
    }
});

// Listener for web navigation events (important for SPAs)
chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.url.startsWith('http://') || details.url.startsWith('https://')) {
        logUrl(details.url);
    }
});

// Auto-reload the extension every 30 minutes to ensure smooth operation
setInterval(() => {
    console.log("Reloading extension for stability...");
    chrome.runtime.reload();
}, 30 * 60 * 1000); // Reload every 30 minutes
  
  

*/