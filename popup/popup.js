// popup.js - AgentShield v0.4 Enhanced
document.addEventListener('DOMContentLoaded', () => {
  const siteEl = document.getElementById('site');
  const scoreEl = document.getElementById('score');
  const scoreNumber = document.getElementById('scoreNumber');
  const scoreText = document.getElementById('scoreText');
  const badge = document.getElementById('badge');
  const issues = document.getElementById('issues');
  const refresh = document.getElementById('refresh');
  const refreshIcon = document.getElementById('refreshIcon');
  const toggleDetails = document.getElementById('toggleDetails');
  const exportReport = document.getElementById('exportReport');
  const clearHistory = document.getElementById('clearHistory');
  const whitelistInput = document.getElementById('whitelistInput');
  const addWhitelist = document.getElementById('addWhitelist');
  const whitelistTags = document.getElementById('whitelistTags');

  let currentReport = null;
  let detailsVisible = true;

  // ===== TAB MANAGEMENT =====
  const tabs = document.querySelectorAll('.tab');
  const tabContents = document.querySelectorAll('.tab-content');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetTab = tab.dataset.tab;
      
      tabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(tc => tc.classList.remove('active'));
      
      tab.classList.add('active');
      document.getElementById(targetTab).classList.add('active');

      // Load data for specific tabs
      if (targetTab === 'history') loadHistory();
      if (targetTab === 'stats') loadStats();
      if (targetTab === 'settings') loadWhitelist();
    });
  });

  // ===== BADGE & SCORE =====
  function setBadge(status) {
    badge.className = 'badge ' + (status || 'unknown');
    const labels = {
      safe: '✓ SÛR',
      unknown: '⚠ ATTENTION',
      suspicious: '⚠ RISQUE'
    };
    badge.textContent = labels[status] || '—';
  }

  function animateScore(targetScore) {
    const duration = 1000;
    const start = parseInt(scoreNumber.textContent) || 0;
    const diff = targetScore - start;
    const startTime = performance.now();

    function update(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      const current = Math.round(start + diff * eased);
      
      scoreNumber.textContent = current;
      document.querySelector('.score-circle').style.setProperty('--score-percentage', current);
      
      if (progress < 1) {
        requestAnimationFrame(update);
      }
    }
    
    requestAnimationFrame(update);
  }

  // ===== RENDER REPORT =====
  function render(report) {
    currentReport = report;

    if (!report || report.error) {
      siteEl.textContent = report?.error || 'Aucun rapport pour cette page.';
      scoreEl.classList.add('hidden');
      setBadge();
      issues.innerHTML = '<div class="empty-state">Cliquez sur "Analyser" pour scanner la page actuelle.</div>';
      return;
    }

    // Site info
    const url = new URL(report.url);
    siteEl.textContent = report.title || url.hostname;
    
    // Score
    scoreEl.classList.remove('hidden');
    animateScore(report.score);
    
    if (report.score >= 80) {
      setBadge('safe');
      scoreText.textContent = 'Excellent - Site sécurisé';
    } else if (report.score >= 50) {
      setBadge('unknown');
      scoreText.textContent = 'Moyen - Vigilance recommandée';
    } else {
      setBadge('suspicious');
      scoreText.textContent = 'Faible - Risques détectés';
    }

    // Build issues list
    issues.innerHTML = '';

    if (report.scoreReasons && report.scoreReasons.length) {
      const h = document.createElement('h4');
      h.textContent = '🔍 Raisons du score';
      issues.appendChild(h);
      const ul = document.createElement('ul');
      report.scoreReasons.forEach(r => {
        const li = document.createElement('li');
        li.innerHTML = `<strong>${r.text}</strong> <span style="color: var(--danger);">(-${r.delta} pts)</span>`;
        ul.appendChild(li);
      });
      issues.appendChild(ul);
    } else {
      const div = document.createElement('div');
      div.className = 'empty-state';
      div.innerHTML = 'Aucun problème de sécurité majeur détecté ! ✓';
      issues.appendChild(div);
    }

    const addList = (title, arr, mapper) => {
      if (!arr || !arr.length) return;
      const h2 = document.createElement('h4');
      h2.textContent = title;
      issues.appendChild(h2);
      const ul = document.createElement('ul');
      arr.slice(0, 10).forEach(item => {
        const li = document.createElement('li');
        li.textContent = mapper ? mapper(item) : (item.snippet || JSON.stringify(item)).slice(0, 200);
        ul.appendChild(li);
      });
      issues.appendChild(ul);
    };

    addList('🔒 Texte caché / Directives', report.hiddenText, itm => {
      const tags = [];
      if (itm.hidden) tags.push('caché');
      if (itm.hasDirective) tags.push('directive');
      if (itm.base64Like) tags.push('base64');
      return `${itm.snippet} [${tags.join(', ')}]`;
    });

    addList('💬 Commentaires suspects', (report.comments || []).filter(c => c.suspect), c => c.text);
    
    addList('📜 Scripts externes', (report.scripts || []).filter(s => 
      s.src && !s.src.includes('youtube.com') && !s.src.includes('google.com')
    ).slice(0, 8), s => s.src);
    
    addList('🖼️ IFrames', report.iframes, f => 
      `${f.src || 'about:blank'} ${f.sandbox ? '(sandboxed ✓)' : '(non-sandboxed ⚠)'}`
    );
    
    addList('🏷️ Meta/Attributs suspects', report.attrs, a => a.snippet);

    // Save to history
    saveToHistory(report);
  }

  // ===== HISTORY =====
  function saveToHistory(report) {
    chrome.storage.local.get('history', data => {
      let history = data.history || [];
      
      // Remove duplicate URL
      history = history.filter(h => h.url !== report.url);
      
      // Add new report
      history.unshift({
        url: report.url,
        title: report.title,
        score: report.score,
        ts: report.ts
      });
      
      // Keep only last 10
      history = history.slice(0, 10);
      
      chrome.storage.local.set({ history });
    });
  }

  function loadHistory() {
    const historyList = document.getElementById('historyList');
    
    chrome.storage.local.get('history', data => {
      const history = data.history || [];
      
      if (history.length === 0) {
        historyList.innerHTML = '<div class="empty-state">Aucun historique disponible</div>';
        return;
      }
      
      historyList.innerHTML = history.map(h => {
        const date = new Date(h.ts).toLocaleDateString('fr-FR', { 
          day: '2-digit', 
          month: '2-digit', 
          hour: '2-digit', 
          minute: '2-digit' 
        });
        const scoreClass = h.score >= 80 ? 'safe' : h.score >= 50 ? 'warning' : 'danger';
        
        return `
          <div class="history-item" data-url="${h.url}">
            <div class="history-title">
              ${h.title || new URL(h.url).hostname}
            </div>
            <div class="history-meta">
              <span>${date}</span>
              <span class="history-score ${scoreClass}">${h.score}/100</span>
            </div>
          </div>
        `;
      }).join('');
      
      // Add click handlers
      document.querySelectorAll('.history-item').forEach(item => {
        item.addEventListener('click', () => {
          const url = item.dataset.url;
          chrome.storage.local.get('lastReport', data => {
            if (data.lastReport && data.lastReport.url === url) {
              render(data.lastReport);
              // Switch to details tab
              document.querySelector('.tab[data-tab="details"]').click();
            }
          });
        });
      });
    });
  }

  // ===== STATS =====
  function loadStats() {
    chrome.storage.local.get(['history', 'globalStats'], data => {
      const history = data.history || [];
      const globalStats = data.globalStats || {
        totalHiddenText: 0,
        totalComments: 0,
        totalScripts: 0,
        totalIframes: 0
      };
      
      const totalScans = history.length;
      const safeCount = history.filter(h => h.score >= 80).length;
      const riskyCount = history.filter(h => h.score < 50).length;
      const avgScore = totalScans > 0 
        ? Math.round(history.reduce((sum, h) => sum + h.score, 0) / totalScans)
        : 0;
      
      document.getElementById('statScans').textContent = totalScans;
      document.getElementById('statAvgScore').textContent = totalScans > 0 ? avgScore : '—';
      document.getElementById('statSafe').textContent = safeCount;
      document.getElementById('statRisky').textContent = riskyCount;
      
      const globalStatsList = document.getElementById('globalStats');
      globalStatsList.innerHTML = `
        <li>${globalStats.totalHiddenText} éléments cachés détectés au total</li>
        <li>${globalStats.totalComments} commentaires analysés</li>
        <li>${globalStats.totalScripts} scripts externes scannés</li>
        <li>${globalStats.totalIframes} iframes détectés</li>
      `;
    });
  }

  // ===== WHITELIST =====
  function loadWhitelist() {
    chrome.storage.local.get('customWhitelist', data => {
      const whitelist = data.customWhitelist || [];
      renderWhitelist(whitelist);
    });
  }

  function renderWhitelist(whitelist) {
    whitelistTags.innerHTML = whitelist.map(domain => `
      <span class="whitelist-tag">
        ${domain}
        <button data-domain="${domain}">×</button>
      </span>
    `).join('');
    
    // Add remove handlers
    whitelistTags.querySelectorAll('button').forEach(btn => {
      btn.addEventListener('click', () => {
        const domain = btn.dataset.domain;
        chrome.storage.local.get('customWhitelist', data => {
          const whitelist = (data.customWhitelist || []).filter(d => d !== domain);
          chrome.storage.local.set({ customWhitelist: whitelist }, () => {
            renderWhitelist(whitelist);
          });
        });
      });
    });
  }

  addWhitelist.addEventListener('click', () => {
    const domain = whitelistInput.value.trim().toLowerCase();
    if (!domain) return;
    
    chrome.storage.local.get('customWhitelist', data => {
      const whitelist = data.customWhitelist || [];
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        chrome.storage.local.set({ customWhitelist: whitelist }, () => {
          whitelistInput.value = '';
          renderWhitelist(whitelist);
        });
      }
    });
  });

  whitelistInput.addEventListener('keypress', e => {
    if (e.key === 'Enter') addWhitelist.click();
  });

  // ===== EXPORT =====
  exportReport.addEventListener('click', () => {
    if (!currentReport) return;
    
    const dataStr = JSON.stringify(currentReport, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agentshield-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // ===== CLEAR HISTORY =====
  clearHistory.addEventListener('click', () => {
    if (confirm('Êtes-vous sûr de vouloir effacer l\'historique ?')) {
      chrome.storage.local.set({ history: [] }, () => {
        loadHistory();
        loadStats();
      });
    }
  });

  // ===== TOGGLE DETAILS =====
  toggleDetails.addEventListener('click', () => {
    detailsVisible = !detailsVisible;
    document.querySelector('.content').style.display = detailsVisible ? 'block' : 'none';
    toggleDetails.textContent = detailsVisible ? '👁️' : '👁️‍🗨️';
  });

  // ===== REFRESH =====
  refresh.addEventListener('click', async () => {
    refreshIcon.innerHTML = '<span class="loader"></span>';
    refresh.disabled = true;
    
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) return;
      
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content.js']
      });
      
      setTimeout(() => {
        chrome.runtime.sendMessage({ type: 'AGENTSHIELD_GET_LAST' }, res => {
          render(res && res.report ? res.report : null);
          refreshIcon.textContent = '🔄';
          refresh.disabled = false;
        });
      }, 800);
    } catch (e) {
      console.error('Injection failed:', e);
      chrome.runtime.sendMessage({ type: 'AGENTSHIELD_GET_LAST' }, res => {
        render(res && res.report ? res.report : null);
        refreshIcon.textContent = '🔄';
        refresh.disabled = false;
      });
    }
  });

  // ===== INITIAL LOAD =====
  chrome.runtime.sendMessage({ type: 'AGENTSHIELD_GET_LAST' }, res => {
    render(res && res.report ? res.report : null);
  });

  // ===== LISTEN FOR UPDATES =====
  chrome.runtime.onMessage.addListener(msg => {
    if (!msg) return;
    if (msg.type === 'AGENTSHIELD_UPDATE') render(msg.report);
  });
});