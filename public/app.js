/* cert-inspector frontend */
(function () {
  'use strict';

  const form = document.getElementById('inspect-form');
  const urlInput = document.getElementById('url-input');
  const submitBtn = document.getElementById('submit-btn');
  const loadingEl = document.getElementById('loading');
  const loadingText = document.getElementById('loading-text');
  const errorEl = document.getElementById('error');
  const resultsEl = document.getElementById('results');
  const cacheIndicator = document.getElementById('cache-indicator');
  const inspectedAt = document.getElementById('inspected-at');
  const exportBtn = document.getElementById('export-btn');
  const summaryBar = document.getElementById('summary-bar');
  const themeToggle = document.getElementById('theme-toggle');
  const clearCacheBtn = document.getElementById('clear-cache-btn');

  let lastResult = null;
  let lastUrl = null;

  // --- Theme ---
  const savedTheme = localStorage.getItem('cert-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);

  themeToggle.addEventListener('click', function () {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('cert-theme', next);
  });

  // --- Tabs ---
  document.querySelectorAll('.tab').forEach(function (tab) {
    tab.addEventListener('click', function () {
      document.querySelectorAll('.tab').forEach(function (t) { t.classList.remove('active'); });
      document.querySelectorAll('.view').forEach(function (v) { v.classList.remove('active'); v.classList.add('hidden'); });
      tab.classList.add('active');
      var view = document.getElementById('view-' + tab.dataset.tab);
      view.classList.remove('hidden');
      view.classList.add('active');
    });
  });

  // --- Helpers ---
  function esc(str) {
    var el = document.createElement('span');
    el.textContent = str;
    return el.innerHTML;
  }

  function formatDate(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  var cfLogo = '<svg class="cf-icon" viewBox="0 0 65 28" xmlns="http://www.w3.org/2000/svg"><path d="M45.8 21.7l1.5-5.2c.3-.9.2-1.8-.2-2.4-.4-.6-1.1-1-1.9-1.1l-18.6-.3c-.1 0-.3-.1-.3-.2-.1-.1 0-.3.1-.3.1-.1.2-.1.3-.2l18.9-.3c2-.1 4.2-1.7 5-3.7l1-2.5c.1-.1.1-.3 0-.4C49.9 2.2 46.7 0 43 0c-4.4 0-8.1 2.9-9.4 6.8-.9-.7-2-.8-3-.4-1 .5-1.6 1.4-1.8 2.4 0 .2-.1.4-.1.6-3.3.1-5.9 2.7-5.9 6 0 .3 0 .7.1 1l.1.4h22c.2 0 .4-.1.5-.2l.3-.9z" fill="#F6821F"/><path d="M51.3 10.1h-.5l-.2.7-1 3.3c-.3.9-.2 1.8.2 2.4.4.6 1.1 1 1.9 1.1l4 .3c.1 0 .3.1.3.2.1.1 0 .3-.1.3-.1.1-.2.2-.3.2l-4.3.3c-2 .1-4.2 1.7-5 3.7l-.3.7c-.1.1 0 .2.2.2H59c.1 0 .3-.1.3-.2 1-1.7 1.7-3.7 1.7-5.8 0-4.1-3.4-7.4-7.5-7.4h-2.2z" fill="#FBAD41"/></svg>';

  function cfBadge(cert) {
    if (!cert || cert.protocol !== 'TLS (CT)') return '';
    return '<span class="cf-badge" title="Behind Cloudflare CDN — certificate data sourced from Certificate Transparency logs, not a direct TLS handshake">' + cfLogo + '</span>';
  }

  function show(el) { el.classList.remove('hidden'); }
  function hide(el) { el.classList.add('hidden'); }

  // --- Form submit ---
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var url = urlInput.value.trim();
    if (!url) return;
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
    urlInput.value = url;
    runInspection(url);
  });

  async function runInspection(url) {
    hide(errorEl);
    hide(resultsEl);
    show(loadingEl);
    submitBtn.disabled = true;
    loadingText.textContent = 'Launching headless browser\u2026';

    try {
      var resp = await fetch('/api/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url }),
      });

      var data = await resp.json();

      if (!resp.ok) {
        throw new Error(data.error || 'Inspection failed');
      }

      lastResult = data;
      lastUrl = url;
      var cacheHit = resp.headers.get('X-Cache') === 'HIT';

      renderResults(data, cacheHit);
    } catch (err) {
      errorEl.textContent = err.message;
      show(errorEl);
    } finally {
      hide(loadingEl);
      submitBtn.disabled = false;
    }
  }

  // --- Render results ---
  function renderResults(data, cacheHit) {
    // Meta
    if (cacheHit) {
      cacheIndicator.innerHTML = '<span class="cache-hit">CACHED</span>';
      show(clearCacheBtn);
    } else {
      cacheIndicator.innerHTML = '<span class="cache-miss">FRESH</span>';
      hide(clearCacheBtn);
    }
    inspectedAt.textContent = 'Inspected: ' + formatDate(data.inspectedAt);

    // Summary bar
    var s = data.summary;
    summaryBar.innerHTML =
      '<div class="stat-card"><div class="count">' + s.totalDomains + '</div><div class="label">Total</div></div>' +
      '<div class="stat-card healthy"><div class="count">' + s.healthy + '</div><div class="label">Healthy</div></div>' +
      '<div class="stat-card expiring"><div class="count">' + s.expiring + '</div><div class="label">Expiring</div></div>' +
      '<div class="stat-card expired"><div class="count">' + s.expired + '</div><div class="label">Expired</div></div>' +
      '<div class="stat-card no-https"><div class="count">' + s.noHttps + '</div><div class="label">No HTTPS</div></div>';

    renderDetailTable(data.domains);
    renderSummaryCards(data.domains);
    renderTimeline(data.domains);

    show(resultsEl);
  }

  // --- Detail table ---
  function renderDetailTable(domains) {
    var container = document.getElementById('view-detail');
    var html = '<table class="detail-table"><thead><tr>' +
      '<th>Domain</th><th>Status</th><th>Issuer</th><th>Expires</th>' +
      '</tr></thead><tbody>';

    domains.forEach(function (d, i) {
      var cert = d.cert;
      var status = cert ? cert.status : 'no-https';
      var statusLabel = status === 'no-https' ? 'No HTTPS' : status.charAt(0).toUpperCase() + status.slice(1);

      html += '<tr class="domain-row" data-idx="' + i + '">' +
        '<td>' + esc(d.domain) + cfBadge(cert) + '</td>' +
        '<td><span class="badge ' + esc(status) + '">' + esc(statusLabel) + '</span></td>' +
        '<td>' + esc(cert && cert.issuer ? cert.issuer : '—') + '</td>' +
        '<td>' + (cert && cert.validTo ? formatDate(cert.validTo) : '—') + '</td>' +
        '</tr>';

      // Expand row
      html += '<tr class="expand-row"><td colspan="4"><div class="expand-content"><dl>';
      html += '<dt>Subject</dt><dd>' + esc(cert && cert.subjectName ? cert.subjectName : '—') + '</dd>';
      html += '<dt>Protocol</dt><dd>' + esc(cert && cert.protocol ? cert.protocol : '—') + '</dd>';
      html += '<dt>Valid From</dt><dd>' + (cert && cert.validFrom ? formatDate(cert.validFrom) : '—') + '</dd>';
      html += '<dt>Days Left</dt><dd>' + (cert ? cert.daysUntilExpiry : '—') + '</dd>';

      if (cert && cert.sans && cert.sans.length) {
        html += '<dt>SANs</dt><dd class="sans-list">' + cert.sans.map(function (s) { return esc(s); }).join(', ') + '</dd>';
      }

      // DNS
      var dns = d.dns;
      if (dns.a.length) { html += '<dt>A</dt><dd>' + dns.a.map(function (r) { return esc(r); }).join(', ') + '</dd>'; }
      if (dns.aaaa.length) { html += '<dt>AAAA</dt><dd>' + dns.aaaa.map(function (r) { return esc(r); }).join(', ') + '</dd>'; }
      if (dns.cname.length) { html += '<dt>CNAME</dt><dd>' + dns.cname.map(function (r) { return esc(r); }).join(', ') + '</dd>'; }

      html += '</dl></div></td></tr>';
    });

    html += '</tbody></table>';
    container.innerHTML = html;

    // Toggle expand
    container.querySelectorAll('.domain-row').forEach(function (row) {
      row.addEventListener('click', function () {
        row.classList.toggle('open');
      });
    });
  }

  // --- Summary cards ---
  function renderSummaryCards(domains) {
    var container = document.getElementById('view-summary');
    var html = '<div class="summary-grid">';

    domains.forEach(function (d) {
      var cert = d.cert;
      var status = cert ? cert.status : 'no-https';

      html += '<div class="domain-card ' + esc(status) + '">';
      html += '<div class="card-domain">' + esc(d.domain) + cfBadge(cert) + '</div>';
      html += '<span class="badge ' + esc(status) + '">' + esc(status === 'no-https' ? 'No HTTPS' : status) + '</span>';
      if (cert && cert.issuer) {
        html += '<div class="card-issuer">' + esc(cert.issuer) + '</div>';
      }
      if (cert && cert.validTo) {
        html += '<div class="card-expiry">Expires: ' + formatDate(cert.validTo) + ' (' + cert.daysUntilExpiry + 'd)</div>';
      }
      html += '</div>';
    });

    html += '</div>';
    container.innerHTML = html;
  }

  // --- Timeline ---
  function renderTimeline(domains) {
    var container = document.getElementById('view-timeline');

    // Filter to only domains with cert dates
    var withCerts = domains.filter(function (d) { return d.cert && d.cert.validTo && d.cert.status !== 'no-https'; });

    if (!withCerts.length) {
      container.innerHTML = '<p style="color:var(--text-muted)">No TLS certificates to display.</p>';
      return;
    }

    // Sort by days until expiry (ascending)
    withCerts.sort(function (a, b) { return a.cert.daysUntilExpiry - b.cert.daysUntilExpiry; });

    var maxDays = Math.max.apply(null, withCerts.map(function (d) { return Math.max(d.cert.daysUntilExpiry, 1); }));
    // Clamp scale to at least 365 for readability
    var scale = Math.max(maxDays, 365);
    var warningPct = (30 / scale) * 100;

    var html = '<div class="timeline-container">';

    withCerts.forEach(function (d) {
      var cert = d.cert;
      var pct = Math.max((Math.max(cert.daysUntilExpiry, 0) / scale) * 100, 0.5);

      html += '<div class="timeline-row">';
      html += '<div class="timeline-label">' + esc(d.domain) + cfBadge(cert) + '</div>';
      html += '<div class="timeline-bar-wrap">';
      html += '<div class="timeline-bar ' + esc(cert.status) + '" style="width:' + pct + '%"></div>';
      html += '<div class="timeline-warning-line" style="left:' + warningPct + '%"></div>';
      html += '</div>';
      html += '<div class="timeline-days">' + cert.daysUntilExpiry + 'd</div>';
      html += '</div>';
    });

    html += '</div>';
    container.innerHTML = html;
  }

  // --- Clear Cache ---
  clearCacheBtn.addEventListener('click', async function () {
    if (!lastUrl) return;
    clearCacheBtn.disabled = true;
    clearCacheBtn.textContent = 'Clearing\u2026';
    try {
      await fetch('/api/cache', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: lastUrl }),
      });
      runInspection(lastUrl);
    } finally {
      clearCacheBtn.disabled = false;
      clearCacheBtn.textContent = 'Clear Cache';
    }
  });

  // --- Export ---
  exportBtn.addEventListener('click', function () {
    if (!lastResult) return;
    var blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'cert-inspection-' + new Date().toISOString().slice(0, 10) + '.json';
    a.click();
    URL.revokeObjectURL(a.href);
  });
})();
