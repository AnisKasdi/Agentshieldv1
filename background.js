// background.js
let lastReport = null;

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return;
  if (msg.type === 'AGENTSHIELD_REPORT') {
    lastReport = msg.report;
    chrome.storage.local.set({lastReport});
    // broadcast update to popup
    chrome.runtime.sendMessage({type: 'AGENTSHIELD_UPDATE', report: lastReport});
    return;
  }

  if (msg.type === 'AGENTSHIELD_GET_LAST') {
    chrome.storage.local.get('lastReport', data => {
      sendResponse({report: data && data.lastReport ? data.lastReport : lastReport});
    });
    return true; // async response
  }
});
