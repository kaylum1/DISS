

/*
let lastLoggedUrl = "";

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (
    changeInfo.status === 'complete' &&
    tab.url &&
    (tab.url.startsWith('http://') || tab.url.startsWith('https://'))
  ) {
    // Only log if this URL is different from the last logged one.
    if (tab.url === lastLoggedUrl) {
      return;
    }
    lastLoggedUrl = tab.url;

    // Update the active tab in storage
    chrome.storage.local.set({ activeTab: tab.url });

    fetch('http://localhost:8000/log', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url })
    })
      .then(response => response.json())
      .then(data => {
        console.log('Logged URL:', data);
        // Save the latest scan results for the popup.
        chrome.storage.local.set({ lastScan: data });
      })
      .catch(error => {
        console.error('Error logging URL:', error);
      });
  }
});

// Listen for tab activation (when the user switches tabs)
chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, function(tab) {
    if (tab && tab.url) {
      chrome.storage.local.set({ activeTab: tab.url });
    }
  });
});

*/

//extension/background.js
// Helper to normalize URLs to their base form (scheme + host + normalized path)
function normalizeUrl(url) {
    try {
      let parsed = new URL(url);
      // Remove trailing slashes from pathname; if empty, use '/'
      let normalizedPath = parsed.pathname.replace(/\/+$/, '');
      if (normalizedPath === '') {
        normalizedPath = '/';
      }
      return parsed.origin + normalizedPath;
    } catch (e) {
      return url;
    }
  }
  
  let lastLoggedUrl = "";
  
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (
      changeInfo.status === 'complete' &&
      tab.url &&
      (tab.url.startsWith('http://') || tab.url.startsWith('https://'))
    ) {
      const normalizedTabUrl = normalizeUrl(tab.url);
      // Only log if this URL is different from the last logged one.
      if (normalizedTabUrl === lastLoggedUrl) {
        return;
      }
      lastLoggedUrl = normalizedTabUrl;
  
      // Update the active tab in storage using normalized URL.
      chrome.storage.local.set({ activeTab: normalizedTabUrl });
  
      fetch('http://localhost:8000/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: tab.url })
      })
        .then(response => response.json())
        .then(data => {
          console.log('Logged URL:', data);
          // Save the latest scan results for the popup.
          // (The server returns the normalized URL.)
          chrome.storage.local.set({ lastScan: data, activeTab: data.url });
        })
        .catch(error => {
          console.error('Error logging URL:', error);
        });
    }
  });
  
  // Listen for tab activation (when the user switches tabs)
  chrome.tabs.onActivated.addListener((activeInfo) => {
    chrome.tabs.get(activeInfo.tabId, function(tab) {
      if (tab && tab.url) {
        const normalizedTabUrl = normalizeUrl(tab.url);
        chrome.storage.local.set({ activeTab: normalizedTabUrl });
      }
    });
  });