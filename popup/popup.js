// popup.js - Refonte UI 2025

document.addEventListener('DOMContentLoaded', () => {
    // ---- DOM Elements ----
    const elements = {
      scoreNumber: document.getElementById('scoreNumber'),
      badgeStatus: document.getElementById('badgeStatus'),
      siteUrl: document.getElementById('siteUrl'),
      scoreMessage: document.getElementById('scoreMessage'),
      progressCircle: document.querySelector('.progress-ring__circle'),
      threatList: document.getElementById('threatList'),
      historyList: document.getElementById('historyList'),
      rescanBtn: document.getElementById('rescanBtn'),
      spinIcon: document.querySelector('.spin-icon'),
      navBtns: document.querySelectorAll('.nav-btn'),
      tabPanes: document.querySelectorAll('.tab-pane'),
      whitelistInput: document.getElementById('whitelistInput'),
      addWhitelistBtn: document.getElementById('addWhitelistBtn'),
      whitelistTags: document.getElementById('whitelistTags'),
      clearBtn: document.getElementById('clearBtn'),
      exportBtn: document.getElementById('exportBtn')
    };
  
    // Circle math
    const radius = elements.progressCircle.r.baseVal.value;
    const circumference = radius * 2 * Math.PI;
    
    // Default Display
    elements.progressCircle.style.strokeDasharray = `${circumference} ${circumference}`;
    elements.progressCircle.style.strokeDashoffset = circumference;
  
    // ---- Navigation ----
    elements.navBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        elements.navBtns.forEach(b => b.classList.remove('active'));
        elements.tabPanes.forEach(t => t.classList.remove('active'));
        
        btn.classList.add('active');
        document.getElementById(btn.dataset.tab).classList.add('active');
        
        // Hide footer button if not on Details
        elements.rescanBtn.style.display = btn.dataset.tab === 'details' ? 'flex' : 'none';
      });
    });
  
    // ---- Init ----
    init();
  
    function init() {
      // Setup current tab info
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs || !tabs[0]) return showPlaceholder();
        const tab = tabs[0];
        
        try {
          const u = new URL(tab.url);
          elements.siteUrl.textContent = u.hostname;
          
          if (u.protocol !== 'http:' && u.protocol !== 'https:') {
            return showPlaceholder("Non applicable");
          }
  
          loadLastReport(tab.id);
  
        } catch (e) {
          elements.siteUrl.textContent = "Page Inconnue";
          showPlaceholder();
        }
      });
  
      loadHistory();
      loadWhitelist();
    }
  
    // ---- Data Loading ----
    function loadLastReport(tabId) {
      chrome.runtime.sendMessage({ action: 'AGENTSHIELD_GET_LAST', tabId }, response => {
        if (response && response.report) {
          updateUI(response.report);
        } else {
          // No report yet, force a scan if valid url
          triggerScan(tabId);
        }
      });
    }
  
    function triggerScan(tabId) {
      setLoading(true);
      chrome.tabs.sendMessage(tabId, { type: 'AGENTSHIELD_TRIGGER_SCAN' }, response => {
        setLoading(false);
        if (response && response.report) {
          updateUI(response.report);
        } else if (chrome.runtime.lastError) {
          showPlaceholder("Analyse impossible. Rechargez la page.");
        }
      });
    }
  
    // ---- UI Update ----
    function updateUI(report) {
      if (report.error) {
        showError(report.error);
        return;
      }
      
      const score = report.score || 0;
      animateScore(score);
      updateStatusTexts(score);
      renderDetails(report);
      
      saveToHistory(report);
      
      // Also fetch network details for the active tab
      chrome.runtime.sendMessage({ action: 'getNetworkData', tabId: null }, response => {
          if (response && response.data) renderNetwork(response.data);
      });
    }
  
    function updateStatusTexts(score) {
      const b = elements.badgeStatus;
      const m = elements.scoreMessage;
      
      b.className = 'status-badge'; // reset
      elements.progressCircle.className.baseVal = 'progress-ring__circle'; // reset
  
      if (score === 100) {
        b.textContent = 'Sûr';
        b.classList.add('safe');
        m.textContent = 'Environnement de navigation sain.';
        elements.progressCircle.classList.add('progress-safe');
      } else if (score >= 70) {
        b.textContent = 'Avertissement';
        b.classList.add('warning');
        m.textContent = 'Prudence : éléments suspects détectés.';
        elements.progressCircle.classList.add('progress-warning');
      } else {
        b.textContent = 'Critique';
        b.classList.add('danger');
        m.textContent = 'Attentions : menaces sérieuses (Injections potentielles).';
        elements.progressCircle.classList.add('progress-danger');
      }
    }
  
    function animateScore(score) {
      let current = 0;
      const duration = 1000;
      const stepTime = Math.abs(Math.floor(duration / score));
      
      // Update text
      const timer = setInterval(() => {
        current += 1;
        elements.scoreNumber.textContent = current;
        if (current >= score) {
          elements.scoreNumber.textContent = score;
          clearInterval(timer);
        }
      }, stepTime || 10);
  
      // Update ring
      setTimeout(() => {
        const offset = circumference - (score / 100) * circumference;
        elements.progressCircle.style.strokeDashoffset = offset;
      }, 50);
    }
  
    // ---- Detailed Rendering (Accordions) ----
    function renderDetails(rep) {
      const container = elements.threatList;
      container.innerHTML = ''; // clear
  
      if (rep.score === 100) {
        container.innerHTML = `
          <div class="empty-state">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="empty-icon"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
            <p>Aucune menace détectée côté client.</p>
          </div>
        `;
        return;
      }
  
      // Render specific groups based on report data
      if (rep.hiddenText && rep.hiddenText.length > 0) {
          container.appendChild(createAccordion(
              "Textes & Directives Cachées", 
              rep.hiddenText.length, 
              rep.hiddenText.some(h => h.severity === 'critical') ? 'danger' : 'warning',
              rep.hiddenText.map(h => h.snippet)
          ));
      }
  
      if (rep.comments && rep.comments.length > 0) {
          container.appendChild(createAccordion(
              "Commentaires Suspects", 
              rep.comments.length, 
              'warning',
              rep.comments.map(c => c.text)
          ));
      }
      
      const suspiciousIframes = rep.iframes ? rep.iframes.filter(f => !f.hasSecurityHeaders && !f.whitelisted) : [];
      if (suspiciousIframes.length > 0) {
           container.appendChild(createAccordion(
              "iFrames non sécurisées", 
              suspiciousIframes.length, 
              'danger',
              suspiciousIframes.map(i => i.src || "about:blank")
          ));
      }
    }
  
    function renderNetwork(requests) {
        // Appends network threats at the bottom of the details tab
        const suspectReqs = requests.filter(r => !isWhitelisted(r.url) && !r.url.startsWith('chrome-extension'));
        if (suspectReqs.length > 0) {
             const container = elements.threatList;
             // Remove empty state if present
             if (container.querySelector('.empty-state')) container.innerHTML = '';
             
             container.appendChild(createAccordion(
                "Requêtes Réseau Furtives", 
                suspectReqs.length, 
                'warning',
                suspectReqs.map(r => `[${r.type.toUpperCase()}] ${r.url.substring(0,60)}...`)
            ));
        }
    }
  
    function createAccordion(title, count, severityClass, items) {
      const group = document.createElement('div');
      group.className = `threat-group ${severityClass}`;
      
      // Header
      const header = document.createElement('button');
      header.className = 'threat-header';
      header.innerHTML = `
        <div class="threat-header-left">
          <span class="threat-badge ${severityClass}">${count}</span>
          ${title}
        </div>
        <svg class="chevron" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="transition: transform 0.2s"><polyline points="6 9 12 15 18 9"></polyline></svg>
      `;
      
      // Body
      const body = document.createElement('div');
      body.className = 'threat-body';
      items.forEach(itemText => {
          const line = document.createElement('div');
          line.className = 'threat-item';
          line.textContent = itemText;
          body.appendChild(line);
      });
      
      header.addEventListener('click', () => {
          group.classList.toggle('open');
      });
  
      group.appendChild(header);
      group.appendChild(body);
      return group;
    }
  
    function showPlaceholder(msg = "Aucun scan actif") {
        elements.scoreNumber.textContent = "--";
        elements.scoreMessage.textContent = msg;
        elements.badgeStatus.textContent = "N/A";
        elements.badgeStatus.className = 'status-badge unknown';
        elements.progressCircle.className.baseVal = 'progress-ring__circle progress-unknown';
        elements.progressCircle.style.strokeDashoffset = circumference;
        elements.threatList.innerHTML = `<div class="empty-state"><p>${msg}</p></div>`;
    }
  
    function showError(err) {
        showPlaceholder("Erreur d'analyse");
        console.error(err);
    }
  
    function setLoading(isLoading) {
        elements.rescanBtn.disabled = isLoading;
        if (isLoading) {
            elements.spinIcon.classList.add('spinning');
            elements.scoreNumber.textContent = "..";
        } else {
            elements.spinIcon.classList.remove('spinning');
        }
    }
  
    // ---- History ----
    function saveToHistory(report) {
      if (!report || !report.url) return;
      try {
        const domain = new URL(report.url).hostname;
        chrome.storage.local.get('history', data => {
          let history = data.history || [];
          
          // Remove duplicate URL
          history = history.filter(h => h.url !== report.url);
          
          // Add new report
          history.unshift({
            url: report.url,
            title: report.title,
            score: report.score,
            ts: report.ts,
            domain: domain
          });
          
          // Keep only last 20
          history = history.slice(0, 20);
          
          chrome.storage.local.set({ history });
        });
      } catch(e){}
    }
  
    function loadHistory() {
      chrome.storage.local.get('history', data => {
        const hist = data.history || [];
        const container = elements.historyList;
        container.innerHTML = '';
  
        if (hist.length === 0) {
          container.innerHTML = `<div class="empty-state"><p>Historique vide.</p></div>`;
          return;
        }
  
        // Show last 15
        [...hist].slice(0, 15).forEach(item => {
          const div = document.createElement('div');
          div.className = 'history-item';
          
          let scoreClass = 'score-t-safe';
          if (item.score < 100) scoreClass = 'score-t-warning';
          if (item.score < 70) scoreClass = 'score-t-danger';
  
          // Gestion des vieux logs "undefined" sans la clé domain
          let displayDomain = item.domain;
          if (!displayDomain && item.url) {
              try { displayDomain = new URL(item.url).hostname; } catch(e) { displayDomain = item.url; }
          }
          if (!displayDomain) displayDomain = "Inconnu";
  
          div.innerHTML = `
            <div>
              <div class="history-domain">${displayDomain}</div>
              <div class="history-date">${new Date(item.ts).toLocaleString()}</div>
            </div>
            <div class="history-score ${scoreClass}">${item.score}</div>
          `;
          container.appendChild(div);
        });
      });
    }
  
    // ---- Settings ----
    function loadWhitelist() {
      chrome.storage.local.get('customWhitelist', data => {
        const list = data.customWhitelist || [];
        renderWhitelist(list);
      });
    }
  
    function renderWhitelist(list) {
      elements.whitelistTags.innerHTML = '';
      list.forEach(domain => {
        const span = document.createElement('span');
        span.className = 'tag';
        span.innerHTML = `
          ${domain}
          <button class="tag-remove" data-domain="${domain}">×</button>
        `;
        span.querySelector('.tag-remove').addEventListener('click', (e) => {
          removeWhitelistDomain(e.target.dataset.domain);
        });
        elements.whitelistTags.appendChild(span);
      });
    }
  
    function addWhitelistDomain() {
      const val = elements.whitelistInput.value.trim().toLowerCase();
      if (!val) return;
      
      // Basic domain check
      const d = val.replace(/^https?:\/\//, '').split('/')[0];
      
      chrome.storage.local.get('customWhitelist', data => {
        let list = data.customWhitelist || [];
        if (!list.includes(d)) {
          list.push(d);
          chrome.storage.local.set({ customWhitelist: list }, () => {
            elements.whitelistInput.value = '';
            renderWhitelist(list);
          });
        }
      });
    }
  
    function removeWhitelistDomain(domain) {
      chrome.storage.local.get('customWhitelist', data => {
        let list = data.customWhitelist || [];
        list = list.filter(d => d !== domain);
        chrome.storage.local.set({ customWhitelist: list }, () => {
          renderWhitelist(list);
        });
      });
    }
  
    function isWhitelisted(url) {
      // Basic static whitelist to cover common requests
      const STATIC = ["google.com", "gstatic.com", "youtube.com"];
      try {
         const u = new URL(url).hostname;
         return STATIC.some(d => u.includes(d));
      } catch(e) { return true; } // Silently ignore bad URLs for network
    }
  
    // ---- Listeners ----
    elements.rescanBtn.addEventListener('click', () => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) triggerScan(tabs[0].id);
      });
    });
  
    elements.addWhitelistBtn.addEventListener('click', addWhitelistDomain);
    elements.whitelistInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') addWhitelistDomain();
    });
  
    elements.clearBtn.addEventListener('click', () => {
      if(confirm("Confirmer la suppression de l'historique ?")) {
          chrome.storage.local.remove('history', () => {
              loadHistory();
          });
      }
    });
  
    // Inter-process updates
    chrome.runtime.onMessage.addListener((request) => {
      if (request.type === 'AGENTSHIELD_UPDATE') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0] && tabs[0].id === request.tabId) {
            updateUI(request.report);
            loadHistory(); // refresh history tab silently
          }
        });
      }
    });
  });