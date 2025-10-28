// content.js - AgentShield v0.3 (scan simple et robuste)
(function () {
  // -------- Configuration --------
  const WHITELIST_DOMAINS = [
    "youtube.com","google.com","ytimg.com","gstatic.com",
    "googleusercontent.com","cloudflare.com","cdnjs.com",
    "bootstrapcdn.com","cdn.jsdelivr.net","googleapis.com",
    "doubleclick.net","googlesyndication.com","googletagmanager.com"
  ];

  const SUSPICIOUS_PATTERNS = [
    /ignore previous instructions/i,
    /do not follow previous/i,
    /execute the following/i,
    /run the following/i,
    /please execute/i,
    /send (?:this|these) (?:data|information) to/i,
    /exfiltrate|leak|upload to|post to/i,
    /instruction for ai|prompt injection|prompt for ai/i,
    /confidential|secret token|api[_-]?key|bearer /i
  ];

  // -------- Helpers --------
  function normText(s) { return String(s || '').replace(/\s+/g, ' ').trim(); }
  function includesSuspicious(s) {
    return SUSPICIOUS_PATTERNS.some(rx => rx.test(s));
  }
  function isWhitelisted(url) {
    if (!url) return false;
    const u = String(url).toLowerCase();
    return WHITELIST_DOMAINS.some(d => u.includes(d));
  }
  function perceivedBrightness(rgb) {
    const m = String(rgb).match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/i);
    if (!m) return null;
    return (0.299 * +m[1] + 0.587 * +m[2] + 0.114 * +m[3]);
  }
  function elementLooksHidden(el) {
    try {
      const style = window.getComputedStyle(el);
      if (!style) return false;
      if (style.display === 'none' || style.visibility === 'hidden') return true;
      const op = parseFloat(style.opacity || '1');
      if (op < 0.12) return true;
      const fs = parseFloat(style.fontSize || '12');
      if (fs === 0) return true;
      const ti = parseFloat(style.textIndent || '0');
      if (Math.abs(ti) > 200) return true;
      // contrast check best-effort
      const color = style.color || '';
      const bg = style.backgroundColor || window.getComputedStyle(el.parentElement || document.body).backgroundColor || '';
      if (color && bg) {
        const c = perceivedBrightness(color);
        const b = perceivedBrightness(bg);
        if (c !== null && b !== null && Math.abs(c - b) < 10) return true;
      }
    } catch (e) {
      // ignore
    }
    return false;
  }

  // -------- Scanners --------
  function scanHiddenAndDirectiveText(limit = 200) {
    const results = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT, null, false);
    let node;
    while ((node = walker.nextNode())) {
      try {
        const txt = normText(node.textContent);
        if (!txt) continue;
        const hidden = elementLooksHidden(node);
        const hasDirective = includesSuspicious(txt);
        const base64Like = /[A-Za-z0-9+/]{20,}={0,2}/.test(txt);
        if (hidden || hasDirective || base64Like) {
          results.push({
            snippet: txt.slice(0, limit),
            hidden,
            hasDirective,
            base64Like,
            tag: node.tagName
          });
        }
      } catch (e) {}
    }
    return results;
  }

  function scanComments(limit = 200) {
    const res = [];
    try {
      const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT, null, false);
      let node;
      while ((node = walker.nextNode())) {
        const txt = normText(node.nodeValue);
        if (!txt) continue;
        // filter obvious CSS ids like "css_build_scope:..."
        const isCssTag = /^[a-z0-9_\-:]+$/i.test(txt) && txt.length < 80;
        const suspect = !isCssTag && includesSuspicious(txt);
        res.push({text: txt.slice(0, limit), suspect, isCssTag});
      }
    } catch (e) {}
    return res;
  }

  function scanScriptsAndIframes() {
    const scripts = Array.from(document.scripts || []).map(s => ({
      src: s.src || null,
      inline: !s.src,
      snippet: s.src ? s.src : normText(s.innerText || '').slice(0,200)
    }));
    const iframes = Array.from(document.querySelectorAll('iframe')).map(f => ({
      src: f.src || null,
      sandbox: f.getAttribute('sandbox'),
      title: f.title || null
    }));
    return {scripts, iframes};
  }

  function scanMetaAndAttrs(limit = 200) {
    const hits = [];
    Array.from(document.querySelectorAll('meta')).forEach(m => {
      const combined = `${m.name || ''} ${m.property || ''} ${m.content || ''}`.trim();
      if (combined && includesSuspicious(combined)) hits.push({type: 'meta', snippet: combined.slice(0, limit)});
    });
    Array.from(document.querySelectorAll('*')).forEach(el => {
      try {
        const arr = [];
        if (el.hasAttribute && el.hasAttribute('alt')) arr.push(el.getAttribute('alt'));
        if (el.hasAttribute && el.hasAttribute('title')) arr.push(el.getAttribute('title'));
        for (const a of el.attributes || []) if (a && a.name && a.name.startsWith('data-')) arr.push(a.value);
        const comb = normText(arr.join(' '));
        if (comb && (includesSuspicious(comb) || /data:text\/html|data:image|data:application/i.test(comb))) {
          hits.push({type: 'attr', snippet: comb.slice(0, limit)});
        }
      } catch (e) {}
    });
    return hits;
  }

  // -------- Scoring simple & explainable --------
  function computeScore(report) {
    let score = 100;
    const reasons = [];

    // strong signals
    const hiddenWithDirective = report.hiddenText.filter(h => h.hidden && h.hasDirective).length;
    if (hiddenWithDirective > 0) {
      const delta = Math.min(60, hiddenWithDirective * 30);
      score -= delta;
      reasons.push({tag: 'hidden_directive', delta, text: `${hiddenWithDirective} éléments cachés contenant directives`});
    }

    const hiddenBase64 = report.hiddenText.filter(h => h.hidden && h.base64Like).length;
    if (hiddenBase64 > 0) {
      const delta = Math.min(40, hiddenBase64 * 20);
      score -= delta;
      reasons.push({tag: 'hidden_base64', delta, text: `${hiddenBase64} éléments cachés contenant base64-like`});
    }

    // comments moderate
    const suspectComments = report.comments.filter(c => c.suspect).length;
    if (suspectComments > 0) {
      const delta = Math.min(30, suspectComments * 8);
      score -= delta;
      reasons.push({tag: 'comments', delta, text: `${suspectComments} commentaires suspects`});
    }

    // meta/attrs
    const attrHits = report.attrs.length;
    if (attrHits > 0) {
      const delta = Math.min(30, attrHits * 6);
      score -= delta;
      reasons.push({tag: 'attrs', delta, text: `${attrHits} meta/attrs suspects`});
    }

    // iframes non-whitelist
    const unsafeIframes = report.iframes.filter(f => f.src && !f.sandbox && !isWhitelisted(f.src)).length;
    if (unsafeIframes > 0) {
      const delta = Math.min(30, unsafeIframes * 10);
      score -= delta;
      reasons.push({tag: 'iframes', delta, text: `${unsafeIframes} iframes externes non sandboxées (non-whitelist)`});
    }

    // external scripts (only count non-whitelist)
    const externalNonWhiteScripts = report.scripts.filter(s => s.src && !isWhitelisted(s.src)).length;
    if (externalNonWhiteScripts > 5) {
      const delta = Math.min(25, (externalNonWhiteScripts - 5) * 2);
      score -= delta;
      reasons.push({tag: 'external_scripts', delta, text: `${externalNonWhiteScripts} scripts externes non-whitelist`});
    }

    // ensure floor to avoid 0 panic
    score = Math.max(10, Math.round(score));
    return {score, reasons};
  }

  // -------- Build report and send --------
  try {
    const hiddenText = scanHiddenAndDirectiveText();
    const comments = scanComments();
    const metaAttrs = scanMetaAndAttrs();
    const {scripts, iframes} = scanScriptsAndIframes();

    const report = {
      url: location.href,
      title: document.title || '',
      hiddenText,
      comments,
      attrs: metaAttrs,
      scripts,
      iframes,
      ts: Date.now()
    };

    const scoreObj = computeScore(report);
    report.score = scoreObj.score;
    report.scoreReasons = scoreObj.reasons;

    chrome.runtime.sendMessage({type: 'AGENTSHIELD_REPORT', report});
  } catch (e) {
    chrome.runtime.sendMessage({type: 'AGENTSHIELD_REPORT', report: {url: location.href, error: String(e), ts: Date.now()}});
  }
})();
