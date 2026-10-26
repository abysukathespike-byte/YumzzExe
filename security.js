/* =====================================================================
 * security.js — YumzExe
 * Lapisan keamanan sisi klien. Load PALING AWAL di <head>.
 *
 * CATATAN JUJUR:
 *  - Semua proteksi di file ini bisa dilewati orang yang paham browser,
 *    karena kode berjalan di komputer mereka sendiri.
 *  - Keamanan yang sebenarnya ada di server: Supabase RLS + Edge Function
 *    yang memverifikasi Firebase ID token.
 *  - File ini mengurangi serangan umum: XSS, clickjacking, spam, injeksi
 *    script, dan salah pakai API dari console.
 * ===================================================================== */
(function () {
  'use strict';
  if (typeof window === 'undefined' || window.Sec) return;

  /* ───────── KONFIGURASI ───────── */
  const CONFIG = Object.freeze({
    forceHttps: true,
    blockEval: true,
    blockDevShortcuts: true,
    idleLogoutMs: 60 * 60 * 1000,
    maxInputLength: 2000,
    integrityIntervalMs: 5000,
    allowedFetchHosts: [
      'googleapis.com', 'gstatic.com', 'firebaseapp.com', 'firebaseio.com',
      'supabase.co', 'scriptblox.com', 'corsproxy.io', 'ui-avatars.com',
      'roblox.com', 'rbxcdn.com', 'nexadev.my.id', 'synoxcloud.xyz',
      'cloudflare.com', 'jsdelivr.net', 'whatsapp.com'
    ],
    allowedOpenHosts: [
      'whatsapp.com', 'vercel.app', 'scriptblox.com', 'roblox.com', 'rawscripts.net',
      'delta.filenetwork.vip', 'vegax.gg', 'firebaseapp.com', 'google.com'
    ],
    allowedScriptHosts: ['cdnjs.cloudflare.com', 'www.gstatic.com', 'cdn.jsdelivr.net', 'fonts.googleapis.com'],
    allowedFrameHosts: ['firebaseapp.com', 'google.com', 'googleapis.com', 'gstatic.com'],
    allowedMessageHosts: ['firebaseapp.com', 'google.com', 'googleapis.com', 'gstatic.com', 'web.app']
  });

  /* ───────── DAFTAR PROTEKSI (untuk audit) ───────── */
  const MEASURES = [
    'HTTPS paksa di domain produksi',
    'Anti-clickjacking (frame-busting)',
    'Halaman disembunyikan saat di-iframe',
    'Blok eval()',
    'Blok setTimeout/setInterval berbasis string',
    'Blok document.write()',
    'Whitelist host untuk fetch()',
    'Blok fetch ke protokol tidak aman',
    'Whitelist window.open()',
    'Blok link javascript:/vbscript:/data:',
    'rel="noopener noreferrer" otomatis di link _blank',
    'Blok script dari host tidak dikenal',
    'Blok script inline yang disisipkan dinamis',
    'Blok iframe/object/embed dari host tidak dikenal',
    'Blok tag <base> dan meta refresh yang disisipkan',
    'Hapus atribut href/src/action berbahaya',
    'Referrer policy ketat',
    'Whitelist origin postMessage',
    'Sanitasi HTML (allowlist tag & atribut)',
    'escapeHtml()',
    'escapeAttr()',
    'Normalisasi input (NFKC)',
    'Hapus karakter kontrol & zero-width/bidi',
    'Batas panjang input',
    'Validasi email',
    'Validasi username',
    'Validasi URL https',
    'Safe JSON parse (batas ukuran & anti prototype pollution)',
    'Safe storage (prefix, blok data sensitif, batas ukuran)',
    'Random ID aman (crypto.getRandomValues)',
    'Rate limit berbasis jendela waktu',
    'Cooldown aksi',
    'Anti-spam chat (duplikat, karakter berulang, caps)',
    'Honeypot anti bot',
    'Cegah double submit form',
    'Auto logout saat idle',
    'Blok shortcut DevTools (F12, Ctrl+Shift+I/J/C, Ctrl+U)',
    'Blok drop file ke halaman',
    'Sanitasi paste ke input',
    'Log error terpusat tanpa stack ke UI',
    'Integrity watch (pulihkan fetch/open jika ditimpa)',
    'Object Sec dibekukan (Object.freeze)',
    'Clear session (hapus data yz_)',
    'Buffer log keamanan'
  ];

  /* ───────── HELPER DASAR ───────── */
  const hostMatches = (host, list) => !!host && list.some(h => host === h || host.endsWith('.' + h));
  const isLocalHost = h => h === 'localhost' || h === '127.0.0.1';
  const parseUrl = u => { try { return new URL(String(u ?? ''), location.href); } catch (_) { return null; } };
  const DANGEROUS_URL = /^\s*(javascript|vbscript|data):/i;

  const events = [];
  const logEvent = (type, detail) => {
    const entry = { t: Date.now(), type, detail: String(detail ?? '').slice(0, 200) };
    events.push(entry);
    if (events.length > 200) events.shift();
    try { console.warn('[Sec]', type, entry.detail); } catch (_) {}
  };

  /* 1. HTTPS paksa */
  if (CONFIG.forceHttps && location.protocol === 'http:' && !isLocalHost(location.hostname)) {
    location.replace('https:' + location.href.slice(5));
  }

  /* 2–3. Anti-clickjacking */
  if (window.top !== window.self) {
    logEvent('framed', location.href);
    try { window.top.location = window.self.location; }
    catch (_) { document.documentElement.style.display = 'none'; }
  }

  /* 4. Blok eval */
  const evalStub = function () { logEvent('blocked', 'eval'); throw new Error('Blocked: eval'); };
  if (CONFIG.blockEval) window.eval = evalStub;

  /* 5. Blok timer berbasis string */
  const origSetTimeout = window.setTimeout.bind(window);
  const origSetInterval = window.setInterval.bind(window);
  window.setTimeout = function (fn, ms, ...rest) {
    if (typeof fn !== 'function') { logEvent('blocked', 'setTimeout(string)'); return 0; }
    return origSetTimeout(fn, ms, ...rest);
  };
  window.setInterval = function (fn, ms, ...rest) {
    if (typeof fn !== 'function') { logEvent('blocked', 'setInterval(string)'); return 0; }
    return origSetInterval(fn, ms, ...rest);
  };

  /* 6. Blok document.write */
  document.write = document.writeln = function () { logEvent('blocked', 'document.write'); };

  /* 7–9. Guard fetch & window.open */
  const originalFetch = window.fetch.bind(window);
  const guardedFetch = function (input, init) {
    const raw = typeof input === 'string' || input instanceof URL ? input : (input && input.url);
    const u = parseUrl(raw);
    if (!u) return Promise.reject(new TypeError('Blocked: URL tidak valid'));
    const okProto = u.protocol === 'https:'
      || (u.protocol === 'http:' && isLocalHost(u.hostname))
      || (location.protocol === 'file:' && u.protocol === 'file:');
    if (!okProto) { logEvent('blocked', 'fetch proto ' + u.protocol); return Promise.reject(new TypeError('Blocked: protokol tidak aman')); }
    if (u.hostname !== location.hostname && !hostMatches(u.hostname, CONFIG.allowedFetchHosts)) {
      logEvent('blocked', 'fetch host ' + u.hostname);
      return Promise.reject(new TypeError('Blocked: host tidak diizinkan'));
    }
    return originalFetch(input, init);
  };
  window.fetch = guardedFetch;

  const originalOpen = window.open.bind(window);
  const guardedOpen = function (url, target, features) {
    const raw = url == null ? '' : String(url);
    if (raw === '' || raw === 'about:blank') return originalOpen(url, target, features);
    const u = parseUrl(raw);
    if (u && (u.origin === location.origin || (u.protocol === 'https:' && hostMatches(u.hostname, CONFIG.allowedOpenHosts)))) {
      return originalOpen(url, target, features);
    }
    logEvent('blocked', 'open ' + raw.slice(0, 120));
    return null;
  };
  window.open = guardedOpen;

  /* 10–11. Link berbahaya & rel aman */
  const addRel = a => {
    const set = new Set((a.getAttribute('rel') || '').split(/\s+/).filter(Boolean));
    set.add('noopener');
    set.add('noreferrer');
    a.setAttribute('rel', [...set].join(' '));
  };
  document.addEventListener('click', e => {
    const a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
    if (a && DANGEROUS_URL.test(a.getAttribute('href') || '')) {
      e.preventDefault();
      logEvent('blocked', 'link ' + a.getAttribute('href').slice(0, 80));
    }
  }, true);

  /* 16. Referrer policy */
  if (!document.querySelector('meta[name="referrer"]')) {
    const m = document.createElement('meta');
    m.name = 'referrer';
    m.content = 'strict-origin-when-cross-origin';
    (document.head || document.documentElement).appendChild(m);
  }

  /* 12–15. Observer: script, iframe, base, meta refresh, atribut berbahaya */
  const scriptOk = src => {
    const u = parseUrl(src);
    return !!u && u.protocol === 'https:' && (u.hostname === location.hostname || hostMatches(u.hostname, CONFIG.allowedScriptHosts));
  };
  const frameOk = src => {
    if (!src || src === 'about:blank') return true;
    const u = parseUrl(src);
    return !!u && u.protocol === 'https:' && hostMatches(u.hostname, CONFIG.allowedFrameHosts);
  };
  const scrub = node => {
    if (node.nodeType !== 1) return;
    const tag = node.tagName;
    if (tag === 'SCRIPT') {
      const src = node.getAttribute('src');
      if (!scriptOk(src)) { logEvent('blocked', 'script ' + (src || 'inline')); node.remove(); }
      return;
    }
    if (tag === 'IFRAME' || tag === 'OBJECT' || tag === 'EMBED') {
      const src = node.getAttribute('src') || node.getAttribute('data') || '';
      if (!frameOk(src)) { logEvent('blocked', tag.toLowerCase() + ' ' + src.slice(0, 80)); node.remove(); }
      return;
    }
    if (tag === 'BASE' || (tag === 'META' && /^refresh$/i.test(node.getAttribute('http-equiv') || ''))) {
      logEvent('blocked', tag.toLowerCase());
      node.remove();
      return;
    }
    if (tag === 'A' && node.getAttribute('target') === '_blank') addRel(node);
    ['href', 'src', 'action', 'formaction'].forEach(attr => {
      const v = node.getAttribute(attr);
      if (v && DANGEROUS_URL.test(v) && !/^\s*data:image\//i.test(v)) node.removeAttribute(attr);
    });
  };
  const SCAN = 'script,iframe,object,embed,base,meta,a[target],[href],[src],[action],[formaction]';
  const startObserver = () => {
    document.querySelectorAll('a[target="_blank"]').forEach(addRel);
    new MutationObserver(muts => {
      for (const m of muts) {
        for (const n of m.addedNodes) {
          if (n.nodeType !== 1) continue;
          scrub(n);
          n.querySelectorAll(SCAN).forEach(scrub);
        }
      }
    }).observe(document.documentElement, { childList: true, subtree: true });
  };
  // Mulai setelah semua script statis selesai dimuat, supaya script app tidak ikut terhapus
  if (document.readyState === 'complete') startObserver();
  else window.addEventListener('load', startObserver);

  /* 18. Whitelist origin postMessage */
  window.addEventListener('message', e => {
    const u = parseUrl(e.origin);
    const ok = e.origin === location.origin
      || (!!u && u.protocol === 'https:' && hostMatches(u.hostname, CONFIG.allowedMessageHosts));
    if (!ok) { logEvent('blocked', 'message ' + e.origin); e.stopImmediatePropagation(); }
  }, true);

  /* 19. Sanitasi HTML (allowlist) */
  const TAGS = new Set(['B', 'STRONG', 'I', 'EM', 'U', 'BR', 'P', 'SPAN', 'DIV', 'SMALL', 'CODE', 'UL', 'OL', 'LI', 'A', 'IMG']);
  const ATTRS = {
    A: ['href', 'title', 'target', 'rel'],
    IMG: ['src', 'alt', 'width', 'height'],
    SPAN: ['class'], DIV: ['class'], P: ['class'], CODE: ['class'], SMALL: ['class']
  };
  const safeUrl = (v, isImg) => {
    const s = String(v ?? '').replace(/[\u0000-\u001F\u007F\s]+/g, '').toLowerCase();
    if (s.startsWith('https://') || s.startsWith('//') || s.startsWith('/') || s.startsWith('#')) return true;
    return isImg && s.startsWith('data:image/') && !s.startsWith('data:image/svg');
  };
  const cleanNode = parent => {
    [...parent.childNodes].forEach(child => {
      if (child.nodeType === 3) return;
      if (child.nodeType !== 1) { child.remove(); return; }
      const tag = child.tagName;
      if (!TAGS.has(tag)) { child.remove(); return; }
      const allowed = ATTRS[tag] || [];
      [...child.attributes].forEach(a => {
        const name = a.name.toLowerCase();
        if (!allowed.includes(name)) { child.removeAttribute(a.name); return; }
        if ((name === 'href' || name === 'src') && !safeUrl(a.value, name === 'src' && tag === 'IMG')) {
          child.removeAttribute(a.name);
        }
      });
      if (tag === 'A') {
        if (child.getAttribute('target') === '_blank') child.setAttribute('rel', 'noopener noreferrer');
        else child.removeAttribute('target');
      }
      cleanNode(child);
    });
  };
  const sanitizeHtml = html => {
    const t = document.createElement('template');
    t.innerHTML = String(html ?? '');
    cleanNode(t.content);
    return t.innerHTML;
  };

  /* 20–25. Escape & normalisasi input */
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' };
  const escapeHtml = v => String(v ?? '').replace(/[&<>"'`]/g, c => ESC[c]);
  const escapeAttr = v => String(v ?? '').replace(/[&<>"'`\n\r]/g, c => (ESC[c] || (c === '\n' ? '&#10;' : '&#13;')));

  const cleanText = (v, max = CONFIG.maxInputLength) => {
    let s = String(v ?? '').normalize('NFKC');
    s = s.replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g, '');
    s = s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
    s = s.replace(/\r\n?/g, '\n');
    return s.trim().slice(0, max);
  };

  /* 26–28. Validator */
  const validateEmail = v => {
    const s = String(v ?? '');
    return s.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s);
  };
  const validateUsername = v => /^[A-Za-z0-9_.]{3,20}$/.test(String(v ?? ''));
  const validateHttpsUrl = (v, hosts) => {
    const u = parseUrl(v);
    if (!u || u.protocol !== 'https:') return false;
    return !hosts || hostMatches(u.hostname, hosts);
  };

  /* 29. Safe JSON parse */
  const safeJsonParse = (str, maxBytes = 100000) => {
    if (typeof str !== 'string' || str.length > maxBytes) return null;
    try {
      return JSON.parse(str, (k, v) =>
        (k === '__proto__' || k === 'constructor' || k === 'prototype') ? undefined : v);
    } catch (_) { return null; }
  };

  /* 30. Safe storage */
  const SENSITIVE = /pass|token|secret|key|auth|credential/i;
  const safeStorage = {
    get(k) {
      try {
        const v = localStorage.getItem('yz_' + k);
        return v == null ? null : safeJsonParse(v);
      } catch (_) { return null; }
    },
    set(k, v) {
      if (SENSITIVE.test(k)) { logEvent('blocked', 'storage ' + k); return false; }
      try {
        const s = JSON.stringify(v);
        if (!s || s.length > 65536) return false;
        localStorage.setItem('yz_' + k, s);
        return true;
      } catch (_) { return false; }
    },
    remove(k) { try { localStorage.removeItem('yz_' + k); } catch (_) {} }
  };

  /* 31. Random ID aman */
  const randomId = (bytes = 16) => {
    const a = new Uint8Array(bytes);
    crypto.getRandomValues(a);
    return [...a].map(b => b.toString(16).padStart(2, '0')).join('');
  };

  /* 32–33. Rate limit & cooldown */
  const buckets = new Map();
  const rateLimit = (key, max, windowMs) => {
    const now = Date.now();
    const arr = (buckets.get(key) || []).filter(t => now - t < windowMs);
    if (arr.length >= max) { buckets.set(key, arr); return false; }
    arr.push(now);
    buckets.set(key, arr);
    return true;
  };
  const cooldown = (key, ms) => rateLimit(key, 1, ms);

  /* 34. Anti-spam chat */
  let lastChat = { text: '', at: 0 };
  const chatSpamCheck = text => {
    const s = String(text ?? '');
    if (/(.)\1{9,}/.test(s)) return { ok: false, reason: 'Terlalu banyak karakter berulang.' };
    const letters = s.replace(/[^a-zA-Z]/g, '');
    if (letters.length >= 15 && letters === letters.toUpperCase()) return { ok: false, reason: 'Jangan pakai huruf kapital semua.' };
    const now = Date.now();
    if (s === lastChat.text && now - lastChat.at < 15000) return { ok: false, reason: 'Pesan yang sama barusan sudah dikirim.' };
    lastChat = { text: s, at: now };
    return { ok: true };
  };

  /* 35. Honeypot */
  const addHoneypot = form => {
    const i = document.createElement('input');
    i.type = 'text';
    i.name = 'website';
    i.tabIndex = -1;
    i.autocomplete = 'off';
    i.setAttribute('aria-hidden', 'true');
    i.style.cssText = 'position:absolute;left:-9999px;opacity:0;height:0;width:0;';
    form.appendChild(i);
  };
  const honeypotTriggered = form => {
    const i = form.querySelector('input[name="website"]');
    return !!(i && i.value);
  };

  /* 36. Cegah double submit */
  const guardSubmit = (form, handler) => {
    form.addEventListener('submit', async e => {
      e.preventDefault();
      if (form.dataset.busy === '1') return;
      form.dataset.busy = '1';
      const btns = [...form.querySelectorAll('button, input[type=submit]')];
      btns.forEach(b => { b.disabled = true; });
      try { await handler(e); }
      catch (err) { logEvent('error', err && err.message); }
      finally {
        form.dataset.busy = '0';
        btns.forEach(b => { b.disabled = false; });
      }
    });
  };

  /* 37. Auto logout saat idle */
  let lastActive = Date.now();
  ['pointerdown', 'keydown', 'touchstart', 'scroll'].forEach(ev =>
    window.addEventListener(ev, () => { lastActive = Date.now(); }, { passive: true }));
  origSetInterval(() => {
    if (Date.now() - lastActive < CONFIG.idleLogoutMs) return;
    if (typeof auth !== 'undefined' && auth && auth.currentUser) {
      logEvent('idle', 'auto logout');
      lastActive = Date.now();
      auth.signOut().finally(() => location.reload());
    }
  }, 30000);

  /* 38. Blok shortcut DevTools (deterrence saja) */
  if (CONFIG.blockDevShortcuts) {
    window.addEventListener('keydown', e => {
      const k = (e.key || '').toLowerCase();
      const blocked = k === 'f12'
        || (e.ctrlKey && e.shiftKey && (k === 'i' || k === 'j' || k === 'c'))
        || (e.ctrlKey && k === 'u');
      if (blocked) { e.preventDefault(); logEvent('blocked', 'shortcut ' + k); }
    }, true);
  }

  /* 39. Blok drop file ke halaman */
  ['dragover', 'drop'].forEach(type => window.addEventListener(type, e => {
    const t = e.target;
    if (t && t.closest && t.closest('input, textarea')) return;
    e.preventDefault();
    if (type === 'drop') logEvent('blocked', 'file drop');
  }));

  /* 40. Sanitasi paste ke input & textarea */
  document.addEventListener('paste', e => {
    const t = e.target;
    if (!(t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement)) return;
    const raw = (e.clipboardData || window.clipboardData || { getData: () => null }).getData('text');
    if (raw == null) return;
    e.preventDefault();
    const max = t.maxLength > 0 ? t.maxLength : CONFIG.maxInputLength;
    const cleaned = cleanText(raw, max);
    const start = t.selectionStart ?? t.value.length;
    const end = t.selectionEnd ?? start;
    t.setRangeText(cleaned, start, end, 'end');
    t.dispatchEvent(new Event('input', { bubbles: true }));
  }, true);

  /* 41. Log error terpusat (tanpa stack ke UI) */
  window.addEventListener('error', e => logEvent('error', e.message));
  window.addEventListener('unhandledrejection', e =>
    logEvent('rejection', (e.reason && e.reason.message) || e.reason));

  /* 42. Integrity watch: pulihkan jika fetch/open/eval ditimpa */
  origSetInterval(() => {
    if (window.fetch !== guardedFetch) { logEvent('tamper', 'fetch'); window.fetch = guardedFetch; }
    if (window.open !== guardedOpen) { logEvent('tamper', 'open'); window.open = guardedOpen; }
    if (CONFIG.blockEval && window.eval !== evalStub) { logEvent('tamper', 'eval'); window.eval = evalStub; }
  }, CONFIG.integrityIntervalMs);

  /* 44. Clear session */
  const clearSession = () => {
    try {
      Object.keys(localStorage).filter(k => k.startsWith('yz_')).forEach(k => localStorage.removeItem(k));
      sessionStorage.clear();
    } catch (_) {}
  };

  /* ───────── API PUBLIK (dibekukan agar tidak bisa ditimpa) ───────── */
  const Sec = {
    cleanText, escapeHtml, escapeAttr, sanitizeHtml,
    validateEmail, validateUsername, validateHttpsUrl,
    safeJsonParse, storage: safeStorage, randomId,
    rateLimit, cooldown, chatSpamCheck,
    addHoneypot, honeypotTriggered, guardSubmit,
    clearSession,
    events: () => events.slice(),
    measures: () => MEASURES.slice(),
    measureCount: MEASURES.length
  };
  window.Sec = Object.freeze(Sec);
})();
