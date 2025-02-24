//extension/settings.js

/*
document.addEventListener('DOMContentLoaded', function () {
  const adBlockerToggle = document.getElementById('adBlockerToggle');
  const cookieDeclinerToggle = document.getElementById('cookieDeclinerToggle');
  const vpnToggle = document.getElementById('vpnToggle');

  // Retrieve and set saved settings; default to false if not set.
  chrome.storage.local.get(
    ['adBlockerEnabled', 'cookieDeclinerEnabled', 'vpnEnabled'],
    function(result) {
      adBlockerToggle.checked = result.adBlockerEnabled === true;
      cookieDeclinerToggle.checked = result.cookieDeclinerEnabled === true;
      vpnToggle.checked = result.vpnEnabled === true;
    }
  );

  // Save changes when the user toggles the switches.
  adBlockerToggle.addEventListener('change', function() {
    chrome.storage.local.set({ 'adBlockerEnabled': adBlockerToggle.checked }, function() {
      console.log('Ad Blocker setting saved:', adBlockerToggle.checked);
      // TODO: Add code to enable/disable ad blocking in your background/content scripts.
    });
  });

  cookieDeclinerToggle.addEventListener('change', function() {
    chrome.storage.local.set({ 'cookieDeclinerEnabled': cookieDeclinerToggle.checked }, function() {
      console.log('Automatic Cookie Decliner setting saved:', cookieDeclinerToggle.checked);
      // TODO: Add code to automatically decline cookies (e.g., via content scripts) if enabled.
    });
  });

  vpnToggle.addEventListener('change', function() {
    chrome.storage.local.set({ 'vpnEnabled': vpnToggle.checked }, function() {
      console.log('VPN setting saved:', vpnToggle.checked);
      // TODO: Add code to enable/disable VPN functionality. This might involve communicating
      // with a VPN extension API or service.
    });
  });

  // Back button returns to the main popup page.
  document.getElementById('backBtn').addEventListener('click', function() {
    window.location.href = 'popup.html';
  });
});

*/


document.addEventListener('DOMContentLoaded', function () {
  const adBlockerToggle = document.getElementById('adBlockerToggle');
  const cookieDeclinerToggle = document.getElementById('cookieDeclinerToggle');
  const vpnToggle = document.getElementById('vpnToggle');

  // Retrieve and set saved settings; default to false if not set.
  chrome.storage.local.get(
    ['adBlockerEnabled', 'cookieDeclinerEnabled', 'vpnEnabled'],
    function(result) {
      adBlockerToggle.checked = result.adBlockerEnabled === true;
      cookieDeclinerToggle.checked = result.cookieDeclinerEnabled === true;
      vpnToggle.checked = result.vpnEnabled === true;
    }
  );

  // Save changes when the user toggles the switches.
  adBlockerToggle.addEventListener('change', function() {
    chrome.storage.local.set({ 'adBlockerEnabled': adBlockerToggle.checked }, function() {
      console.log('Ad Blocker setting saved:', adBlockerToggle.checked);
    });
  });

  cookieDeclinerToggle.addEventListener('change', function() {
    chrome.storage.local.set({ 'cookieDeclinerEnabled': cookieDeclinerToggle.checked }, function() {
      console.log('Automatic Cookie Decliner setting saved:', cookieDeclinerToggle.checked);
    });
  });

  vpnToggle.addEventListener('change', function() {
    chrome.storage.local.set({ 'vpnEnabled': vpnToggle.checked }, function() {
      console.log('VPN setting saved:', vpnToggle.checked);
    });
  });

  // Back button returns to the main popup page.
  document.getElementById('backBtn').addEventListener('click', function() {
    window.location.href = 'popup.html';
  });
});


