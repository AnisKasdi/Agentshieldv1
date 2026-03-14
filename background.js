// Service Worker pour Manifest V3
// Gestion des requêtes réseau et analyse des headers

const analyzedRequests = new Map();

// Écoute des requêtes pour détecter les patterns de blocage
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (details.tabId > 0) {
      const ua = details.requestHeaders.find(h => h.name.toLowerCase() === 'user-agent');
      
      if (!analyzedRequests.has(details.tabId)) {
        analyzedRequests.set(details.tabId, {
          requests: [],
          userAgents: new Set()
        });
      }
      
      const tabData = analyzedRequests.get(details.tabId);
      tabData.requests.push({
        url: details.url,
        type: details.type,
        userAgent: ua ? ua.value : null
      });
      
      if (ua) {
        tabData.userAgents.add(ua.value);
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// Écoute des réponses pour détecter les protections
chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.tabId > 0 && analyzedRequests.has(details.tabId)) {
      const tabData = analyzedRequests.get(details.tabId);
      const request = tabData.requests.find(r => r.url === details.url);
      
      if (request) {
        request.statusCode = details.statusCode;
        request.responseHeaders = details.responseHeaders;
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Nettoyage des données lorsqu'un onglet est fermé
chrome.tabs.onRemoved.addListener((tabId) => {
  analyzedRequests.delete(tabId);
});

// API pour récupérer les données analysées
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getNetworkData') {
    const tabData = analyzedRequests.get(request.tabId) || { requests: [], userAgents: new Set() };
    sendResponse({
      requests: tabData.requests,
      userAgents: Array.from(tabData.userAgents)
    });
  } else if (request.type === 'AGENTSHIELD_REPORT') {
    // Stockage du rapport reçu par le content.js
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId) {
      if (!analyzedRequests.has(tabId)) {
        analyzedRequests.set(tabId, { requests: [], userAgents: new Set() });
      }
      analyzedRequests.get(tabId).lastReport = request.report;
    }
    // Renvoyer aux autres parties de l'extension (ex: popup ouvert)
    chrome.runtime.sendMessage({ type: 'AGENTSHIELD_UPDATE', report: request.report }).catch(() => {});
  } else if (request.type === 'AGENTSHIELD_GET_LAST') {
    // Le popup demande le dernier rapport pour un onglet donné
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      const tabData = analyzedRequests.get(tabId);
      sendResponse({ report: tabData ? tabData.lastReport : null });
    });
    return true; // Indique une réponse asynchrone
  }
  return true;
});

// Initialisation
chrome.runtime.onInstalled.addListener(() => {
  console.log('AgentCheck extension installée avec succès');
});