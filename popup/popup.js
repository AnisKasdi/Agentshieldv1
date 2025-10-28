// popup.js
document.addEventListener('DOMContentLoaded', () => {
  const siteEl = document.getElementById('site');
  const scoreEl = document.getElementById('score');
  const badge = document.getElementById('badge');
  const issues = document.getElementById('issues');
  const details = document.getElementById('details');
  const refresh = document.getElementById('refresh');

  function setBadge(status) {
    badge.className = 'badge ' + (status || 'unknown');
    if (status === 'safe') badge.textContent = 'SAFE';
    else if (status === 'unknown') badge.textContent = 'ATTENTION';
    else if (status === 'suspicious') badge.textContent = 'SUSPICIOUS';
    else badge.textContent = '—';
  }

  function render(report) {
    if (!report) {
      siteEl.textContent = 'Aucun rapport pour cette page.';
      scoreEl.textContent = '';
      setBadge();
      details.classList.add('hidden');
      return;
    }

    siteEl.textContent = report.title ? `${report.title}` : report.url;
    scoreEl.textContent = `IA Safety Score : ${report.score} / 100`;

    if (report.score >= 80) setBadge('safe');
    else if (report.score >= 50) setBadge('unknown');
    else setBadge('suspicious');

    // build issues
    issues.innerHTML = '';

    if (report.scoreReasons && report.scoreReasons.length) {
      const h = document.createElement('h4'); h.textContent = 'Pourquoi le score est bas :';
      issues.appendChild(h);
      const ul = document.createElement('ul');
      report.scoreReasons.forEach(r => {
        const li = document.createElement('li');
        li.textContent = `${r.text} (malus: -${r.delta})`;
        ul.appendChild(li);
      });
      issues.appendChild(ul);
    }

    const addList = (title, arr, mapper) => {
      if (!arr || !arr.length) return;
      const h2 = document.createElement('h4'); h2.textContent = title;
      issues.appendChild(h2);
      const ul = document.createElement('ul');
      arr.slice(0,8).forEach(item => {
        const li = document.createElement('li');
        li.textContent = mapper ? mapper(item) : (item.snippet || JSON.stringify(item)).slice(0,200);
        ul.appendChild(li);
      });
      issues.appendChild(ul);
    };

    addList('Texte potentiellement caché / directives', report.hiddenText, itm => {
      const tags = [];
      if (itm.hidden) tags.push('hidden');
      if (itm.hasDirective) tags.push('directive');
      if (itm.base64Like) tags.push('base64-like');
      return `${itm.snippet} — [${tags.join(', ')}]`;
    });

    addList('Commentaires suspects', (report.comments || []).filter(c => c.suspect), c => c.text);
    addList('Scripts (extraits)', (report.scripts || []).filter(s => s.src && !(String(s.src).includes('youtube.com') || String(s.src).includes('google.com'))), s => s.src || s.snippet);
    addList('IFrames', report.iframes, f => f.src ? `${f.src} ${f.sandbox ? '(sandboxed)' : ''}` : JSON.stringify(f));
    addList('Meta/Attrs suspects', report.attrs, a => a.snippet);

    details.classList.remove('hidden');
  }

  // request last stored report
  chrome.runtime.sendMessage({type: 'AGENTSHIELD_GET_LAST'}, res => {
    const rpt = res && res.report ? res.report : null;
    render(rpt);
  });

  // listen for live updates when content script sends new report
  chrome.runtime.onMessage.addListener((msg) => {
    if (!msg) return;
    if (msg.type === 'AGENTSHIELD_UPDATE') render(msg.report);
  });

  // refresh button: try to inject content.js on active tab (and fallback: content script auto-run will do it on load)
  refresh.addEventListener('click', async () => {
    try {
      const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
      if (!tab) return;
      // inject content.js explicitly (some pages allow it)
      await chrome.scripting.executeScript({target: {tabId: tab.id}, files: ['content.js']});
      // then ask background for last report (it should be updated by content.js)
      setTimeout(() => {
        chrome.runtime.sendMessage({type: 'AGENTSHIELD_GET_LAST'}, res => {
          render(res && res.report ? res.report : null);
        });
      }, 600); // small delay to let content script post message
    } catch (e) {
      console.error('Injection failed:', e);
      // fallback: just reload last known
      chrome.runtime.sendMessage({type: 'AGENTSHIELD_GET_LAST'}, res => {
        render(res && res.report ? res.report : null);
      });
    }
  });
});
