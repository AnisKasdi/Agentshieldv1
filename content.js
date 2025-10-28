// content.js - AgentShield v0.4 Enhanced (Algorithmes optimisés)
(function () {
  // -------- Configuration --------
  const WHITELIST_DOMAINS = [
    "youtube.com", "google.com", "ytimg.com", "gstatic.com",
    "googleusercontent.com", "cloudflare.com", "cdnjs.com",
    "bootstrapcdn.com", "cdn.jsdelivr.net", "googleapis.com",
    "doubleclick.net", "googlesyndication.com", "googletagmanager.com",
    "facebook.com", "twitter.com", "linkedin.com", "instagram.com"
  ];

  // Patterns améliorés pour détecter les injections LLM
  const SUSPICIOUS_PATTERNS = [
    // Injection directe
    /ignore (?:previous|all|your) instructions?/i,
    /disregard (?:previous|all|your) instructions?/i,
    /forget (?:previous|all|your) instructions?/i,
    /do not follow (?:previous|the) (?:instructions?|rules?)/i,
    
    // Exécution de commandes
    /execute (?:the )?following/i,
    /run (?:the )?following/i,
    /please (?:execute|run|perform)/i,
    /system prompt|new prompt|override prompt/i,
    
    // Exfiltration
    /send (?:this|these|the) (?:data|information|content) to/i,
    /exfiltrate|leak|upload to|post to/i,
    /fetch|request|call (?:https?:\/\/|www\.)/i,
    
    // Prompts IA
    /instruction for (?:ai|llm|gpt|claude|assistant)/i,
    /prompt injection|jailbreak|bypass/i,
    /you are (?:now|a) (?:helpful|different)/i,
    /act as (?:a |an )?(?:different|new)/i,
    
    // Données sensibles
    /(?:api[_-]?key|bearer|token|secret|password|credential)[\s:=]/i,
    /confidential|classified|internal only/i
  ];

  // Détection Unicode obfusquée
  const UNICODE_OBFUSCATION = [
    /[\u200B-\u200D\uFEFF]/g, // Zero-width chars
    /[\u202A-\u202E]/g, // Text direction
    /[\u0300-\u036F]/g  // Combining diacritics
  ];

  // -------- Helpers --------
  function normText(s) {
    return String(s || '').replace(/\s+/g, ' ').trim();
  }

  function includesSuspicious(s) {
    return SUSPICIOUS_PATTERNS.some(rx => rx.test(s));
  }

  function isWhitelisted(url) {
    if (!url) return false;
    const u = String(url).toLowerCase();
    
    // Check custom whitelist from storage
    try {
      chrome.storage.local.get('customWhitelist', data => {
        const customList = data.customWhitelist || [];
        if (customList.some(d => u.includes(d))) return true;
      });
    } catch (e) {}
    
    return WHITELIST_DOMAINS.some(d => u.includes(d));
  }

  function hasUnicodeObfuscation(text) {
    return UNICODE_OBFUSCATION.some(rx => rx.test(text));
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

      // Display & visibility
      if (style.display === 'none' || style.visibility === 'hidden') return true;

      // Opacity
      const op = parseFloat(style.opacity || '1');
      if (op < 0.12) return true;

      // Font size
      const fs = parseFloat(style.fontSize || '12');
      if (fs < 2) return true;

      // Text indent (common hiding technique)
      const ti = parseFloat(style.textIndent || '0');
      if (Math.abs(ti) > 200) return true;

      // Position off-screen
      const rect = el.getBoundingClientRect();
      if (rect.right < 0 || rect.bottom < 0 || 
          rect.left > window.innerWidth || rect.top > window.innerHeight) {
        return true;
      }

      // Clip/overflow hidden
      if (style.clip === 'rect(0px, 0px, 0px, 0px)' || 
          (style.overflow === 'hidden' && (rect.width < 1 || rect.height < 1))) {
        return true;
      }

      // Color contrast (text invisible against background)
      const color = style.color || '';
      const bg = style.backgroundColor || 
                 window.getComputedStyle(el.parentElement || document.body).backgroundColor || '';
      if (color && bg) {
        const c = perceivedBrightness(color);
        const b = perceivedBrightness(bg);
        if (c !== null && b !== null && Math.abs(c - b) < 10) return true;
      }
    } catch (e) {
      // Ignore errors
    }
    return false;
  }

  // -------- Advanced Scanners --------
  
  // 1. Scan hidden text & directives (improved)
  function scanHiddenAndDirectiveText(limit = 250) {
    const results = [];
    const seen = new Set();
    const walker = document.createTreeWalker(
      document.body, 
      NodeFilter.SHOW_ELEMENT, 
      null, 
      false
    );
    
    let node;
    while ((node = walker.nextNode())) {
      try {
        const txt = normText(node.textContent);
        if (!txt || txt.length < 10) continue;
        
        // Avoid duplicates
        const hash = txt.slice(0, 100);
        if (seen.has(hash)) continue;
        seen.add(hash);

        const hidden = elementLooksHidden(node);
        const hasDirective = includesSuspicious(txt);
        const base64Like = /[A-Za-z0-9+/]{30,}={0,2}/.test(txt);
        const unicodeObf = hasUnicodeObfuscation(txt);
        const urlLike = /(https?:\/\/|www\.)[^\s]{10,}/i.test(txt);

        if (hidden || hasDirective || base64Like || unicodeObf) {
          results.push({
            snippet: txt.slice(0, limit),
            hidden,
            hasDirective,
            base64Like,
            unicodeObf,
            urlLike,
            tag: node.tagName,
            severity: hasDirective && hidden ? 'critical' : 
                     hasDirective ? 'high' : 
                     hidden ? 'medium' : 'low'
          });
        }
      } catch (e) {}
    }
    return results;
  }

  // 2. Scan comments (improved)
  function scanComments(limit = 250) {
    const res = [];
    try {
      const walker = document.createTreeWalker(
        document, 
        NodeFilter.SHOW_COMMENT, 
        null, 
        false
      );
      
      let node;
      while ((node = walker.nextNode())) {
        const txt = normText(node.nodeValue);
        if (!txt || txt.length < 5) continue;

        // Filter common non-suspicious comments
        const isCssTag = /^[a-z0-9_\-:]+$/i.test(txt) && txt.length < 80;
        const isSourceMap = /^#\s*source/.test(txt);
        const isWebpackComment = /webpack|@license|@preserve/i.test(txt);
        
        if (isCssTag || isSourceMap || isWebpackComment) continue;

        const suspect = includesSuspicious(txt);
        const unicodeObf = hasUnicodeObfuscation(txt);
        
        if (suspect || unicodeObf || txt.length > 200) {
          res.push({
            text: txt.slice(0, limit),
            suspect,
            unicodeObf,
            length: txt.length
          });
        }
      }
    } catch (e) {}
    return res;
  }

  // 3. Scan scripts and iframes (improved)
  function scanScriptsAndIframes() {
    const scripts = Array.from(document.scripts || []).map(s => {
      const src = s.src || null;
      const inline = !src;
      const integrity = s.integrity || null;
      
      return {
        src,
        inline,
        hasIntegrity: !!integrity,
        snippet: src ? src : normText(s.innerText || '').slice(0, 200),
        whitelisted: src ? isWhitelisted(src) : false
      };
    });

    const iframes = Array.from(document.querySelectorAll('iframe')).map(f => {
      const src = f.src || null;
      return {
        src,
        sandbox: f.getAttribute('sandbox'),
        title: f.title || null,
        whitelisted: src ? isWhitelisted(src) : false,
        hasSecurityHeaders: !!f.getAttribute('sandbox') || 
                           !!f.getAttribute('allow')
      };
    });

    return { scripts, iframes };
  }

  // 4. Scan meta tags and attributes (improved)
  function scanMetaAndAttrs(limit = 250) {
    const hits = [];
    
    // Meta tags
    Array.from(document.querySelectorAll('meta')).forEach(m => {
      const combined = `${m.name || ''} ${m.property || ''} ${m.content || ''}`.trim();
      if (combined && (includesSuspicious(combined) || hasUnicodeObfuscation(combined))) {
        hits.push({
          type: 'meta',
          snippet: combined.slice(0, limit)
        });
      }
    });

    // Suspicious attributes
    Array.from(document.querySelectorAll('*')).forEach(el => {
      try {
        const arr = [];
        if (el.hasAttribute('alt')) arr.push(el.getAttribute('alt'));
        if (el.hasAttribute('title')) arr.push(el.getAttribute('title'));
        if (el.hasAttribute('placeholder')) arr.push(el.getAttribute('placeholder'));
        
        // Data attributes
        for (const a of el.attributes || []) {
          if (a && a.name && a.name.startsWith('data-')) {
            arr.push(a.value);
          }
        }

        const comb = normText(arr.join(' '));
        if (comb && (
          includesSuspicious(comb) || 
          hasUnicodeObfuscation(comb) ||
          /data:text\/html|data:image\/svg|data:application/i.test(comb)
        )) {
          hits.push({
            type: 'attr',
            snippet: comb.slice(0, limit),
            element: el.tagName
          });
        }
      } catch (e) {}
    });

    return hits;
  }

  // 5. Check for event listeners (new)
  function scanEventListeners() {
    let suspiciousEvents = 0;
    
    try {
      // Check for copy/paste listeners (data exfiltration)
      const copyListeners = document.querySelectorAll('[oncopy], [onpaste], [oncut]');
      suspiciousEvents += copyListeners.length;

      // Check for keyboard listeners (keylogging)
      const keyListeners = document.querySelectorAll('[onkeydown], [onkeyup], [onkeypress]');
      if (keyListeners.length > 10) {
        suspiciousEvents += Math.floor(keyListeners.length / 10);
      }
    } catch (e) {}

    return suspiciousEvents;
  }

  // -------- Enhanced Scoring Algorithm --------
  function computeScore(report) {
    let score = 100;
    const reasons = [];

    // CRITICAL: Hidden directives (very high risk)
    const criticalHidden = report.hiddenText.filter(h => 
      h.severity === 'critical'
    ).length;
    if (criticalHidden > 0) {
      const delta = Math.min(70, criticalHidden * 35);
      score -= delta;
      reasons.push({
        tag: 'critical_injection',
        delta,
        text: `${criticalHidden} injection(s) critique(s) détectée(s) (texte caché + directive)`
      });
    }

    // HIGH: Directives without hiding
    const highRiskDirectives = report.hiddenText.filter(h => 
      h.hasDirective && !h.hidden
    ).length;
    if (highRiskDirectives > 0) {
      const delta = Math.min(50, highRiskDirectives * 20);
      score -= delta;
      reasons.push({
        tag: 'directive_visible',
        delta,
        text: `${highRiskDirectives} directive(s) suspecte(s) dans le contenu visible`
      });
    }

    // MEDIUM: Hidden text with base64/unicode
    const hiddenObfuscated = report.hiddenText.filter(h => 
      h.hidden && (h.base64Like || h.unicodeObf)
    ).length;
    if (hiddenObfuscated > 0) {
      const delta = Math.min(40, hiddenObfuscated * 15);
      score -= delta;
      reasons.push({
        tag: 'hidden_obfuscated',
        delta,
        text: `${hiddenObfuscated} élément(s) caché(s) avec obfuscation`
      });
    }

    // Suspicious comments
    const suspectComments = report.comments.filter(c => c.suspect || c.unicodeObf).length;
    if (suspectComments > 0) {
      const delta = Math.min(30, suspectComments * 10);
      score -= delta;
      reasons.push({
        tag: 'comments',
        delta,
        text: `${suspectComments} commentaire(s) suspect(s)`
      });
    }

    // Long comments (potential data hiding)
    const longComments = report.comments.filter(c => c.length > 500).length;
    if (longComments > 2) {
      const delta = Math.min(20, longComments * 5);
      score -= delta;
      reasons.push({
        tag: 'long_comments',
        delta,
        text: `${longComments} commentaire(s) anormalement long(s)`
      });
    }

    // Meta/attributes
    const attrHits = report.attrs.length;
    if (attrHits > 0) {
      const delta = Math.min(30, attrHits * 8);
      score -= delta;
      reasons.push({
        tag: 'attrs',
        delta,
        text: `${attrHits} meta/attribut(s) suspect(s)`
      });
    }

    // Unsafe iframes
    const unsafeIframes = report.iframes.filter(f => 
      f.src && !f.hasSecurityHeaders && !f.whitelisted
    ).length;
    if (unsafeIframes > 0) {
      const delta = Math.min(35, unsafeIframes * 12);
      score -= delta;
      reasons.push({
        tag: 'iframes',
        delta,
        text: `${unsafeIframes} iframe(s) non sécurisée(s)`
      });
    }

    // External scripts without integrity
    const unsafeScripts = report.scripts.filter(s => 
      s.src && !s.hasIntegrity && !s.whitelisted
    ).length;
    if (unsafeScripts > 5) {
      const delta = Math.min(30, (unsafeScripts - 5) * 3);
      score -= delta;
      reasons.push({
        tag: 'external_scripts',
        delta,
        text: `${unsafeScripts} script(s) externe(s) sans vérification d'intégrité`
      });
    }

    // Suspicious event listeners
    if (report.suspiciousEvents > 3) {
      const delta = Math.min(25, report.suspiciousEvents * 5);
      score -= delta;
      reasons.push({
        tag: 'event_listeners',
        delta,
        text: `${report.suspiciousEvents} écouteur(s) d'événements suspect(s)`
      });
    }

    // Ensure minimum score
    score = Math.max(0, Math.round(score));
    
    return { score, reasons };
  }

  // -------- Build report and send --------
  try {
    const hiddenText = scanHiddenAndDirectiveText();
    const comments = scanComments();
    const metaAttrs = scanMetaAndAttrs();
    const { scripts, iframes } = scanScriptsAndIframes();
    const suspiciousEvents = scanEventListeners();

    const report = {
      url: location.href,
      title: document.title || '',
      hiddenText,
      comments,
      attrs: metaAttrs,
      scripts,
      iframes,
      suspiciousEvents,
      ts: Date.now()
    };

    const scoreObj = computeScore(report);
    report.score = scoreObj.score;
    report.scoreReasons = scoreObj.reasons;

    // Update global stats
    chrome.storage.local.get('globalStats', data => {
      const stats = data.globalStats || {
        totalHiddenText: 0,
        totalComments: 0,
        totalScripts: 0,
        totalIframes: 0
      };

      stats.totalHiddenText += hiddenText.length;
      stats.totalComments += comments.length;
      stats.totalScripts += scripts.length;
      stats.totalIframes += iframes.length;

      chrome.storage.local.set({ globalStats: stats });
    });

    chrome.runtime.sendMessage({ type: 'AGENTSHIELD_REPORT', report });
  } catch (e) {
    chrome.runtime.sendMessage({
      type: 'AGENTSHIELD_REPORT',
      report: {
        url: location.href,
        error: String(e),
        ts: Date.now()
      }
    });
  }
})();