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
  

