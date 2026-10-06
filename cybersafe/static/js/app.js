/* ============ CyberSafe shared front-end helpers ============ */

/* ---- tabs ---- */
function initTabs(root) {
  (root || document).querySelectorAll('[data-tabs]').forEach(group => {
    const tabs = group.querySelectorAll('.tab');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const target = tab.dataset.tab;
        tabs.forEach(t => t.classList.toggle('active', t === tab));
        const scope = group.dataset.scope
          ? document.querySelector(group.dataset.scope)
          : group.parentElement;
        scope.querySelectorAll('.tabpane').forEach(p =>
          p.classList.toggle('active', p.dataset.pane === target));
      });
    });
  });
}

/* ---- minimal markdown renderer (safe: escapes first) ---- */
function mdToHtml(md) {
  if (!md) return '';
  let h = md
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const blocks = [];
  h = h.replace(/```(\w*)\n?([\s\S]*?)```/g, (m, lang, code) => {
    blocks.push(`<pre><code>${code.trim()}</code></pre>`);
    return `\u0000BLOCK${blocks.length - 1}\u0000`;
  });

  h = h.replace(/`([^`\n]+)`/g, '<code>$1</code>');
  h = h.replace(/^###\s+(.+)$/gm, '<h3>$1</h3>');
  h = h.replace(/^##\s+(.+)$/gm, '<h2>$1</h2>');
  h = h.replace(/^#\s+(.+)$/gm, '<h1>$1</h1>');
  h = h.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  h = h.replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>');
  h = h.replace(/^\s*[-*+]\s+(.+)$/gm, '\u0001LI\u0001$1');
  h = h.replace(/^\s*(\d+)\.\s+(.+)$/gm, '\u0002LI\u0002$2');
  h = h.replace(/^---+$/gm, '<hr>');

  const lines = h.split('\n');
  let out = '', inUl = false, inOl = false;
  for (let line of lines) {
    if (line.startsWith('\u0001LI\u0001')) {
      if (!inUl) { out += '<ul>'; inUl = true; }
      out += '<li>' + line.slice(4) + '</li>';
      continue;
    }
    if (inUl) { out += '</ul>'; inUl = false; }
    if (line.startsWith('\u0002LI\u0002')) {
      if (!inOl) { out += '<ol>'; inOl = true; }
      out += '<li>' + line.slice(4) + '</li>';
      continue;
    }
    if (inOl) { out += '</ol>'; inOl = false; }
    if (/^<(h[123]|hr|pre)/.test(line.trim()) || line.includes('\u0000BLOCK')) {
      out += line;
    } else if (line.trim()) {
      out += '<p>' + line + '</p>';
    }
  }
  if (inUl) out += '</ul>';
  if (inOl) out += '</ol>';
  out = out.replace(/\u0000BLOCK(\d+)\u0000/g, (m, i) => blocks[i]);
  return out;
}

/* ---- clipboard ---- */
function copyText(text, btn) {
  const done = () => {
    if (!btn) return;
    const old = btn.textContent;
    btn.textContent = '✓ Copied';
    setTimeout(() => { btn.textContent = old; }, 1400);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallback());
  } else fallback();
  function fallback() {
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch (e) {}
    document.body.removeChild(ta);
  }
}

/* ---- fetch helper ---- */
async function postJSON(url, data) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data || {})
  });
  return r.json();
}

/* ---- form loading state ---- */
function initFormLoading() {
  document.querySelectorAll('form[data-loading]').forEach(form => {
    form.addEventListener('submit', () => {
      const btn = form.querySelector('button[type=submit], .btn-submit');
      if (btn && !btn.disabled) {
        btn.dataset.old = btn.innerHTML;
        btn.innerHTML = '<span class="spin"></span> ' + (btn.dataset.loading || 'Analyzing…');
        btn.disabled = true;
        const note = form.querySelector('[data-loading-note]');
        if (note) note.classList.remove('hidden');
      }
    });
  });
}

/* ---- gauge ---- */
function gauge(score, size) {
  size = size || 104;
  const r = size / 2 - 8, c = 2 * Math.PI * r;
  const off = c - (Math.max(0, Math.min(100, score)) / 100) * c;
  const band = score >= 80 ? '#ef4444' : score >= 55 ? '#f97316'
             : score >= 25 ? '#eab308' : '#22c55e';
  return `<svg width="${size}" height="${size}">
    <circle cx="${size/2}" cy="${size/2}" r="${r}" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="8"/>
    <circle cx="${size/2}" cy="${size/2}" r="${r}" fill="none" stroke="${band}" stroke-width="8"
      stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${off}"/>
  </svg>`;
}

/* ---- ollama status poll ---- */
function pollAI() {
  const pill = document.getElementById('aiPill');
  if (!pill) return;
  fetch('/api/ollama/status').then(r => r.json()).then(s => {
    pill.className = 'ai-pill ' + (s.online ? 'ai-on' : 'ai-off');
    pill.innerHTML = '<span class="dot"></span>' +
      (s.online ? 'AI Online · ' + (s.model || '') : 'AI Offline');
  }).catch(() => {});
}

/* ---- mobile nav ---- */
function initMobileNav() {
  const btn = document.getElementById('menuBtn');
  const sb = document.getElementById('sidebar');
  if (!btn || !sb) return;
  btn.addEventListener('click', () => {
    const open = sb.classList.toggle('open');
    btn.textContent = open ? '✕' : '☰';
    btn.setAttribute('aria-expanded', String(open));
  });
  // close after choosing a destination on small screens
  sb.querySelectorAll('.nav a').forEach(a => {
    a.addEventListener('click', () => {
      if (window.innerWidth <= 1000) sb.classList.remove('open');
    });
  });
}

/* ---- init ---- */
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initFormLoading();
  initMobileNav();
  setInterval(pollAI, 30000);

  document.querySelectorAll('[data-copy]').forEach(b => {
    b.addEventListener('click', () => {
      const t = b.dataset.copy || (document.querySelector(b.dataset.copyFrom) || {}).value || '';
      copyText(t, b);
    });
  });

  document.querySelectorAll('[data-fill]').forEach(el => {
    el.addEventListener('click', () => {
      const target = document.querySelector(el.dataset.fillTarget);
      if (target) { target.value = el.dataset.fill; target.focus(); }
    });
  });

  document.querySelectorAll('.bar-f[data-w]').forEach(b => {
    setTimeout(() => { b.style.width = b.dataset.w + '%'; }, 60);
  });
});
