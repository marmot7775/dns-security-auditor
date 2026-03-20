/* ==========================================================================
   DNS Security Auditor - Frontend Application
   v2.0  --  Scoped audits, severity sorting, auto-collapse
   ========================================================================== */

const API_BASE = '/api';

// -- Scope definitions: which checks to show per scope --
const SCOPE_CHECKS = {
    complete:      null, // null = show all
    email_full:    ['DMARC', 'SPF', 'DKIM', 'MX Records', 'MX', 'MTA-STS', 'TLS-RPT', 'BIMI', 'Blocklist'],
    dmarc:         ['DMARC', 'SPF', 'DKIM'],
    transport:     ['MTA-STS', 'TLS-RPT', 'DANE', 'MX Records', 'MX'],
    dns_infra:     ['DNSSEC', 'CAA', 'DANE', 'Nameservers', 'Certificate Transparency'],
    security_scan: ['DMARC', 'SPF', 'DKIM', 'DNSSEC', 'DANE', 'Certificate Transparency', 'Blocklist', 'CAA', 'MTA-STS'],
};

// Severity sort order (lower = higher priority = displayed first)
const SEVERITY_ORDER = { fail: 0, warn: 1, pass: 2 };

const DEFAULT_TITLE = document.title;
let currentScope = 'complete';
let lastAuditData = null;
let auditStartTime = 0;

// -- DOM References --
const auditForm      = document.getElementById('audit-form');
const domainInput    = document.getElementById('domain-input');
const auditBtn       = document.getElementById('audit-btn');
const loadingSection = document.getElementById('loading-section');
const resultsSection = document.getElementById('results-section');

// -- Scope selector --
document.querySelectorAll('.scope-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.scope-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentScope = btn.dataset.scope;
    });
});

// -- DKIM selector toggle --
document.getElementById('selector-toggle').addEventListener('click', (e) => {
    e.preventDefault();
    const field = document.getElementById('selector-field');
    const toggle = document.getElementById('selector-toggle');
    field.classList.toggle('visible');
    toggle.classList.toggle('active');
    if (field.classList.contains('visible')) {
        document.getElementById('selector-input').focus();
    }
});

// -- Check URL for domain parameter on load --
document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const domain = params.get('d');
    const scope  = params.get('scope');
    if (scope && SCOPE_CHECKS[scope]) {
        currentScope = scope;
        document.querySelectorAll('.scope-btn').forEach(b => {
            b.classList.toggle('active', b.dataset.scope === scope);
        });
    }
    if (domain) {
        domainInput.value = domain;
        runAudit(domain);
    } else {
        domainInput.focus();
    }
});

// -- Educational section toggle --
const eduToggle = document.getElementById('edu-toggle');
const eduContent = document.getElementById('edu-content');
if (eduToggle && eduContent) {
    eduToggle.addEventListener('click', () => {
        eduToggle.classList.toggle('open');
        eduContent.classList.toggle('open');
    });
}

// -- Form submission --
auditForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const domain = normalizeDomain(domainInput.value.trim());
    if (!domain) return;
    domainInput.value = domain;
    runAudit(domain);
});

function normalizeDomain(input) {
    if (!input) return '';
    let d = input.toLowerCase().trim();
    if (d.includes('@')) d = d.split('@').pop();
    d = d.replace(/^https?:\/\//, '').replace(/^www\./, '');
    d = d.split('/')[0].split('?')[0].replace(/\.$/, '');
    return d;
}

// -- Main audit runner --
async function runAudit(domain) {
    auditStartTime = performance.now();
    document.title = `Scanning ${domain}...`;
    showLoading();
    hideResults();

    const selectorVal = document.getElementById('selector-input')?.value?.trim() || '';
    let streamUrl = `${API_BASE}/audit/stream?domain=${encodeURIComponent(domain)}`;
    if (selectorVal) streamUrl += `&selector=${encodeURIComponent(selectorVal)}`;
    if (currentScope && currentScope !== 'complete') streamUrl += `&scope=${encodeURIComponent(currentScope)}`;

    try {
        const resp = await fetch(streamUrl);
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `Audit failed (HTTP ${resp.status})`);
        }

        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            // Keep the last incomplete line in the buffer
            buffer = lines.pop();

            for (const line of lines) {
                if (!line.startsWith('data: ')) continue;
                const payload = line.slice(6);
                let msg;
                try { msg = JSON.parse(payload); } catch { continue; }

                if (msg.error) {
                    throw new Error(msg.error);
                }

                if (msg.done) {
                    renderResults(msg.result);
                    return;
                }

                // Progress update
                updateLoadingProgress(msg.step, msg.progress);
            }
        }

        // If we got here without a done message, fall back to JSON endpoint
        throw new Error('Stream ended without results');
    } catch (err) {
        console.error('SSE audit error:', err);
        // Fall back to the regular JSON endpoint
        try {
            let auditUrl = `${API_BASE}/audit?domain=${encodeURIComponent(domain)}`;
            if (selectorVal) auditUrl += `&selector=${encodeURIComponent(selectorVal)}`;
            if (currentScope && currentScope !== 'complete') auditUrl += `&scope=${encodeURIComponent(currentScope)}`;
            const resp = await fetch(auditUrl);
            if (!resp.ok) {
                const fallbackErr = await resp.json().catch(() => ({}));
                throw new Error(fallbackErr.detail || `Audit failed (HTTP ${resp.status})`);
            }
            const data = await resp.json();
            renderResults(data);
        } catch (fallbackErr) {
            console.error('Fallback audit error:', fallbackErr);
            hideLoading();
            showError(fallbackErr.message || 'Audit failed. Please check the domain and try again.');
        }
    }
}

// ============================================================
// Loading / Error
// ============================================================

// Map backend step names to friendly status messages
const STEP_MESSAGES = {
    'Tree Walk':                'Resolving DNS records...',
    'DMARC':                    'Checking DMARC policy...',
    'MX':                       'Checking MX records...',
    'SPF':                      'Analyzing SPF configuration...',
    'MTA-STS':                  'Validating MTA-STS...',
    'TLS-RPT':                  'Checking TLS-RPT...',
    'BIMI':                     'Looking for BIMI record...',
    'DNSSEC':                   'Verifying DNSSEC chain...',
    'CAA':                      'Checking CAA records...',
    'Nameservers':              'Checking nameservers...',
    'DANE':                     'Checking DANE TLSA records...',
    'DKIM':                     'Discovering DKIM selectors...',
    'Certificate Transparency': 'Querying certificate transparency logs...',
    'Blocklist':                'Checking IP and domain blocklists...',
    'Vendor Fingerprinting':    'Fingerprinting email services...',
    'Scoring':                  'Calculating security score...',
};

function showLoading() {
    loadingSection.style.display = 'block';
    const card = loadingSection.querySelector('.loading-card');
    card.innerHTML = `
        <div class="loading-bar-track">
            <div class="loading-bar-fill" id="loading-bar"></div>
        </div>
        <div class="loading-status" id="loading-status">Starting audit...</div>
    `;
    resultsSection.style.display = 'none';
    auditBtn.disabled = true;
    auditBtn.classList.add('is-loading');

    const bar = document.getElementById('loading-bar');
    if (bar) bar.style.width = '0%';
}

function updateLoadingProgress(step, progressPct) {
    const bar = document.getElementById('loading-bar');
    const status = document.getElementById('loading-status');
    if (bar) bar.style.width = Math.min(progressPct, 97) + '%';
    if (status) status.textContent = STEP_MESSAGES[step] || `Checking ${step}...`;
}

function hideLoading() {
    loadingSection.style.display = 'none';
    auditBtn.disabled = false;
    auditBtn.classList.remove('is-loading');
}

function hideResults() {
    resultsSection.style.display = 'none';
}

function showError(message) {
    document.title = DEFAULT_TITLE;
    loadingSection.style.display = 'block';
    const card = loadingSection.querySelector('.loading-card');
    card.innerHTML = `
        <div class="error-title">Audit Failed</div>
        <div class="error-message">${escapeHtml(message)}</div>
        <button class="error-retry" id="retry-btn">Try Again</button>
    `;
    document.getElementById('retry-btn').addEventListener('click', () => {
        const domain = normalizeDomain(domainInput.value.trim());
        if (domain) { runAudit(domain); } else { location.reload(); }
    });
}

// ============================================================
// Render results
// ============================================================

function renderResults(data) {
    lastAuditData = data;

    // Finish loading animation
    const bar = document.getElementById('loading-bar');
    const status = document.getElementById('loading-status');
    if (bar) bar.style.width = '100%';
    if (status) status.textContent = 'Complete';

    const scopeAtRender = currentScope;
    setTimeout(() => {
        hideLoading();
        resultsSection.style.display = 'block';

        // Scroll results into view so user sees the report
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Update URL for sharing
        const url = new URL(window.location);
        url.searchParams.set('d', data.domain);
        url.searchParams.set('scope', scopeAtRender);
        window.history.replaceState({}, '', url);
    }, 300);

    // Domain banner
    document.getElementById('result-domain').textContent = data.domain;

    // Timestamp + duration
    const auditDuration = ((performance.now() - auditStartTime) / 1000).toFixed(1);
    const now = new Date();
    const tsText = now.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
        + ' ' + now.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', timeZoneName: 'short' });
    document.getElementById('result-timestamp').textContent = `${tsText}  \u00b7  ${auditDuration}s`;

    // -- Filter checks by scope --
    let checks = data.checks || [];
    const scopeFilter = SCOPE_CHECKS[currentScope];
    if (scopeFilter) {
        checks = checks.filter(c => {
            const name = (c.name || '').toUpperCase();
            return scopeFilter.some(s => name.includes(s.toUpperCase()));
        });
    }

    // -- Sort: email auth first (DMARC, SPF, DKIM), then severity --
    const PIN_TOP = ['DMARC', 'SPF', 'DKIM'];
    checks.sort((a, b) => {
        const aPin = PIN_TOP.indexOf(a.name);
        const bPin = PIN_TOP.indexOf(b.name);
        const aIsPinned = aPin !== -1;
        const bIsPinned = bPin !== -1;
        // Pinned checks always first, in defined order
        if (aIsPinned && bIsPinned) return aPin - bPin;
        if (aIsPinned) return -1;
        if (bIsPinned) return 1;
        // Everything else sorted by severity
        const sa = SEVERITY_ORDER[a.status] ?? 3;
        const sb = SEVERITY_ORDER[b.status] ?? 3;
        return sa - sb;
    });

    // Summary counts (scoped)
    const passCount = checks.filter(c => c.status === 'pass').length;
    const warnCount = checks.filter(c => c.status === 'warn').length;
    const failCount = checks.filter(c => c.status === 'fail').length;

    document.getElementById('summary-pass').textContent = passCount;
    document.getElementById('summary-warn').textContent = warnCount;
    document.getElementById('summary-fail').textContent = failCount;

    // Tab title with issue summary
    const issues = failCount + warnCount;
    document.title = issues > 0
        ? `(${issues} issue${issues > 1 ? 's' : ''}) ${data.domain} | DNS Audit`
        : `All clear: ${data.domain} | DNS Audit`;

    // Grade color-coding
    const gradeCard = document.querySelector('.grade-card');
    const gradeEl   = document.getElementById('summary-grade');
    const grade = data.score?.grade || '--';
    const isDefensive = data.defensive_dns;

    if (isDefensive) {
        // Non-mail domains get a shield icon instead of a letter grade
        gradeEl.textContent = '\u26E8';
        gradeEl.style.fontSize = '2rem';
        if (gradeCard) {
            gradeCard.style.borderTopColor = '#6366f1';
            gradeCard.style.background = '#eef2ff';
            gradeEl.style.color = '#4338ca';
        }
        // Replace label
        const label = gradeCard?.querySelector('.summary-label');
        if (label) label.textContent = 'Defensive DNS';
    } else {
        gradeEl.textContent = grade;
        gradeEl.style.fontSize = '';
        const gradeColors = {
            'A': { bg: '#ecfdf5', border: '#10b981', text: '#065f46' },
            'B': { bg: '#eff6ff', border: '#3b82f6', text: '#1e40af' },
            'C': { bg: '#fffbeb', border: '#f59e0b', text: '#92400e' },
            'D': { bg: '#fff7ed', border: '#f97316', text: '#9a3412' },
            'F': { bg: '#fef2f2', border: '#ef4444', text: '#991b1b' },
        };
        const gc = gradeColors[grade];
        if (gc && gradeCard) {
            gradeCard.style.borderTopColor = gc.border;
            gradeCard.style.background = gc.bg;
            gradeEl.style.color = gc.text;
        }
        // Restore label in case previous audit was defensive
        const label = gradeCard?.querySelector('.summary-label');
        if (label) label.textContent = 'Security Grade';
    }
    // Score number
    const scoreNum = data.score?.total;
    let scoreEl = document.getElementById('summary-score');
    if (scoreNum !== undefined && gradeCard) {
        if (!scoreEl) {
            scoreEl = document.createElement('div');
            scoreEl.id = 'summary-score';
            scoreEl.className = 'score-subtext';
            gradeEl.parentNode.insertBefore(scoreEl, gradeEl.nextSibling);
        }
        scoreEl.textContent = Math.round(scoreNum) + ' / 100';
    } else if (scoreEl) {
        scoreEl.remove();
    }

    // -- Priority fixes (always at top, before detailed results) --
    const prioritySection = document.getElementById('priority-section');
    const priorityList    = document.getElementById('priority-list');
    priorityList.innerHTML = '';

    const fixes = data.priority_fixes || [];
    if (fixes.length > 0) {
        prioritySection.style.display = 'block';
        fixes.forEach((fix, i) => {
            const item = document.createElement('div');
            item.className = 'priority-item';
            item.innerHTML = `
                <div class="priority-number">${i + 1}</div>
                <div>${escapeHtml(fix)}</div>
            `;
            priorityList.appendChild(item);
        });
    } else {
        prioritySection.style.display = 'none';
    }

    // -- Result cards (sorted, auto-collapse pass) --
    const resultsList = document.getElementById('results-list');
    resultsList.innerHTML = '';

    // -- Defensive DNS callout (inserted before the results list) --
    const existingDefensive = document.getElementById('defensive-dns-card');
    if (existingDefensive) existingDefensive.remove();

    if (data.defensive_dns) {
        const signals = data.defensive_signals || [];
        const signalLabels = {
            'null_mx': 'Null MX (no inbound email)',
            'null_spf': 'Null SPF (no outbound email)',
            'dmarc_reject': 'DMARC reject (block spoofing)',
        };
        const signalHtml = signals.map(s =>
            `<span class="defensive-signal">${escapeHtml(signalLabels[s] || s)}</span>`
        ).join('');

        const defensiveCard = document.createElement('div');
        defensiveCard.id = 'defensive-dns-card';
        defensiveCard.className = 'defensive-dns-card';
        defensiveCard.innerHTML = `
            <div class="defensive-header">Defensive DNS Detected</div>
            <div class="defensive-body">This domain is configured to not send or receive email. The DNS records explicitly reject all email activity, which is a security best practice for non-mail domains.</div>
            <div class="defensive-signals">${signalHtml}</div>
        `;
        resultsList.parentNode.insertBefore(defensiveCard, resultsList);
    }

    // -- Anomalies ("What's Unusual") --
    const anomaliesSection = document.getElementById('anomalies-section');
    const anomaliesList = document.getElementById('anomalies-list');
    anomaliesList.innerHTML = '';

    if (data.anomalies && data.anomalies.length > 0) {
        anomaliesSection.style.display = 'block';
        data.anomalies.forEach(a => {
            const sevClass = {critical: 'fail', high: 'warn', medium: 'info'}[a.severity] || 'info';
            const sevLabel = {critical: 'Critical', high: 'High', medium: 'Medium'}[a.severity] || a.severity;
            const item = document.createElement('div');
            item.className = `anomaly-card anomaly-${sevClass}`;
            item.innerHTML = `
                <div class="anomaly-top">
                    <span class="anomaly-severity ${sevClass}">${sevLabel}</span>
                    <span class="anomaly-title">${escapeHtml(a.title)}</span>
                </div>
                <div class="anomaly-desc">${escapeHtml(a.description)}</div>
                ${a.recommendation ? `<div class="anomaly-rec">${escapeHtml(a.recommendation)}</div>` : ''}
            `;
            anomaliesList.appendChild(item);
        });
    } else {
        anomaliesSection.style.display = 'none';
    }

    checks.forEach((check, i) => {
        // Attach tree walk + DMARC eval data to the DMARC check
        if ((check.name || '').toUpperCase().includes('DMARC') && data.tree_walk) {
            check._tree_walk = data.tree_walk;
        }
        if ((check.name || '').toUpperCase().includes('DMARC') && data.dmarc_eval) {
            check._dmarc_eval = data.dmarc_eval;
        }
        // Attach SPF execution trace + tree to the SPF check
        if ((check.name || '').toUpperCase() === 'SPF' && data.spf_execution) {
            check._spf_execution = data.spf_execution;
        }
        if ((check.name || '').toUpperCase() === 'SPF' && data.spf_tree) {
            check._spf_tree = data.spf_tree;
        }
        // Attach report chain to DMARC check
        if ((check.name || '').toUpperCase().includes('DMARC') && data.report_chain) {
            check._report_chain = data.report_chain;
        }
        const card = createResultCard(check, i);
        resultsList.appendChild(card);
    });

    // Vendors
    const vendorsSection = document.getElementById('vendors-section');
    const vendorsGrid    = document.getElementById('vendors-grid');
    vendorsGrid.innerHTML = '';

    if (data.vendors && data.vendors.length > 0) {
        vendorsSection.style.display = 'block';
        data.vendors.forEach(v => {
            const card = document.createElement('div');
            card.className = 'vendor-card';
            card.innerHTML = `
                <div class="vendor-name">${escapeHtml(v.name)}</div>
                <div class="vendor-confidence">${v.confidence}%</div>
            `;
            vendorsGrid.appendChild(card);
        });
    } else {
        vendorsSection.style.display = 'none';
    }

    // Share button
    document.getElementById('share-btn').onclick = () => {
        _copyToClipboard(window.location.href, document.getElementById('share-btn')?.querySelector('span'), 'Share');
    };

    // "Run another audit" button at bottom of results
    let runAnother = document.getElementById('run-another-btn');
    if (!runAnother) {
        runAnother = document.createElement('div');
        runAnother.id = 'run-another-btn';
        runAnother.className = 'run-another';
        runAnother.innerHTML = `
            <button class="audit-btn run-another-btn" type="button">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
                     stroke-linecap="round" stroke-linejoin="round" width="16" height="16">
                    <polyline points="23 4 23 10 17 10"/>
                    <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                </svg>
                <span>Run Another Audit</span>
            </button>
        `;
        resultsSection.appendChild(runAnother);
        runAnother.querySelector('button').addEventListener('click', () => {
            window.scrollTo({ top: 0, behavior: 'smooth' });
            setTimeout(() => {
                domainInput.value = '';
                domainInput.focus();
            }, 400);
        });
    }
}

// ============================================================
// Result card  --  auto-collapse passing, expand fail/warn
// ============================================================

function createResultCard(check, index) {
    const card = document.createElement('div');
    // Auto-collapse: pass = collapsed, fail/warn = expanded
    // DMARC is always expanded (important check + tree walk visualization)
    const isDmarc = (check.name || '').toUpperCase() === 'DMARC';
    const isExpanded = true;
    card.className = 'result-card expanded';
    card.dataset.status = check.status;
    card.style.animationDelay = `${0.05 + index * 0.04}s`;

    const statusLabel = check.pill_label || {
        pass: 'Pass', warn: 'Warning', fail: 'Issue'
    }[check.status] || 'Unknown';

    card.innerHTML = `
        <div class="result-header">
            <div class="status-dot ${check.status}"></div>
            <div class="result-title">${escapeHtml(check.name)}</div>
            <span class="status-pill ${check.status}">${statusLabel}</span>
            <div class="result-verdict">${escapeHtml(check.verdict || '')}</div>
            <div class="result-chevron">&#9662;</div>
        </div>
        <div class="result-body">
            <div class="result-body-inner">
                ${renderCheckBody(check)}
            </div>
        </div>
    `;

    card.querySelector('.result-header').addEventListener('click', () => {
        card.classList.toggle('expanded');
        card.querySelector('.result-header').setAttribute('aria-expanded',
            card.classList.contains('expanded') ? 'true' : 'false');
    });

    // Keyboard accessibility
    const header = card.querySelector('.result-header');
    header.setAttribute('tabindex', '0');
    header.setAttribute('role', 'button');
    header.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
    header.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            card.classList.toggle('expanded');
            header.setAttribute('aria-expanded',
                card.classList.contains('expanded') ? 'true' : 'false');
        }
    });

    // Copy buttons (DNS record blocks + fix record blocks)
    card.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            let record = '';
            const fixBlock = btn.closest('.fix-record-block');
            if (fixBlock) {
                record = fixBlock.querySelector('.fix-record-value')?.textContent || '';
            } else {
                const block = btn.closest('.record-block');
                record = block?.querySelector('.record-text')?.textContent
                    || block?.textContent?.replace('Copy', '').trim() || '';
            }
            _copyToClipboard(record, btn, 'Copy');
        });
    });

    return card;
}

// ============================================================
// Record syntax highlighting
// ============================================================

function highlightRecord(record, checkName) {
    // Escape first, then wrap known tokens in spans
    const escaped = escapeHtml(record);
    const name = (checkName || '').toUpperCase();

    if (name === 'SPF' || escaped.startsWith('v=spf1')) {
        return highlightSpf(escaped);
    }
    if (name === 'DMARC' || escaped.startsWith('v=DMARC1')) {
        return highlightDmarc(escaped);
    }
    if (name === 'DKIM' || escaped.includes('v=DKIM1')) {
        return highlightDkim(escaped);
    }
    // MX records: highlight priority numbers
    if (name.includes('MX')) {
        return escaped.replace(/^(\d+)\s+/gm, '<span class="rec-muted">$1</span> ');
    }
    return escaped;
}

function highlightSpf(text) {
    return text
        // Dangerous: +all, ?all
        .replace(/\+all\b/g, '<span class="rec-danger">+all</span>')
        .replace(/\?all\b/g, '<span class="rec-warn">?all</span>')
        // Safe: -all, ~all
        .replace(/-all\b/g, '<span class="rec-safe">-all</span>')
        .replace(/~all\b/g, '<span class="rec-neutral">~all</span>')
        // Mechanisms
        .replace(/\b(include:)([^\s]+)/g, '<span class="rec-keyword">$1</span><span class="rec-value">$2</span>')
        .replace(/\b(redirect=)([^\s]+)/g, '<span class="rec-keyword">$1</span><span class="rec-value">$2</span>')
        .replace(/\b(ip4:)([^\s]+)/g, '<span class="rec-keyword">$1</span><span class="rec-muted">$2</span>')
        .replace(/\b(ip6:)([^\s]+)/g, '<span class="rec-keyword">$1</span><span class="rec-muted">$2</span>')
        .replace(/\b(a|mx)\b(?![\w=:-])/g, '<span class="rec-keyword">$1</span>')
        // Version tag
        .replace(/^(v=spf1)\b/, '<span class="rec-muted">$1</span>');
}

function highlightDmarc(text) {
    return text
        // Policy tags -- color by strength
        .replace(/\bp=reject\b/g, '<span class="rec-safe">p=reject</span>')
        .replace(/\bp=quarantine\b/g, '<span class="rec-neutral">p=quarantine</span>')
        .replace(/\bp=none\b/g, '<span class="rec-warn">p=none</span>')
        // Subdomain policy
        .replace(/\bsp=(reject|quarantine|none)\b/g, '<span class="rec-keyword">sp=$1</span>')
        // Reporting
        .replace(/\b(rua=)(mailto:[^\s;]+)/g, '<span class="rec-keyword">$1</span><span class="rec-value">$2</span>')
        .replace(/\b(ruf=)(mailto:[^\s;]+)/g, '<span class="rec-keyword">$1</span><span class="rec-value">$2</span>')
        // Percentage
        .replace(/\b(pct=)(\d+)\b/g, '<span class="rec-keyword">$1</span><span class="rec-value">$2</span>')
        // Alignment
        .replace(/\b(adkim=|aspf=)([rs])\b/g, '<span class="rec-keyword">$1</span><span class="rec-value">$2</span>')
        // Version + fo
        .replace(/^(v=DMARC1)\b/, '<span class="rec-muted">$1</span>')
        .replace(/\b(fo=)([^\s;]+)/g, '<span class="rec-keyword">$1</span><span class="rec-muted">$2</span>');
}

function highlightDkim(text) {
    return text
        .replace(/\b(v=DKIM1)\b/g, '<span class="rec-muted">$1</span>')
        .replace(/\b(k=)(rsa|ed25519)/g, '<span class="rec-keyword">$1</span><span class="rec-value">$2</span>')
        .replace(/\b(p=)([A-Za-z0-9+/=]+)/g, '<span class="rec-keyword">$1</span><span class="rec-muted">$2</span>')
        .replace(/\b(h=)([^\s;]+)/g, '<span class="rec-keyword">$1</span><span class="rec-value">$2</span>')
        .replace(/\b(t=)([^\s;]+)/g, '<span class="rec-keyword">$1</span><span class="rec-value">$2</span>');
}

function _renderDetailItem(d) {
    const typeClass = {
        error: 'fail-item', warning: 'warn-item',
        info: 'info-item', good: 'pass-item'
    }[d.type] || 'info-item';
    const icon = {
        error: '&#10005;', warning: '&#9888;',
        info: '&#8250;', good: '&#10003;'
    }[d.type] || '&#8250;';
    return `
        <div class="detail-item ${typeClass}">
            <span class="detail-icon">${icon}</span>
            <span>${escapeHtml(d.text || '')}</span>
        </div>
    `;
}

function renderCheckBody(check) {
    let html = '';

    // Explanation (always visible -- the impact statement)
    if (check.explanation) {
        html += `<div class="explanation">${sanitizeHtml(check.explanation)}</div>`;
    }

    // Split details into critical (error/warning) vs informational (info/good)
    const criticalDetails = [];
    const infoDetails = [];
    if (check.details && check.details.length > 0) {
        const detailOrder = { error: 0, warning: 1, info: 2, good: 3 };
        const sorted = [...check.details].sort((a, b) =>
            (detailOrder[a.type] ?? 4) - (detailOrder[b.type] ?? 4)
        );
        sorted.forEach(d => {
            if (d.type === 'error' || d.type === 'warning') {
                criticalDetails.push(d);
            } else {
                infoDetails.push(d);
            }
        });
    }

    // All details -- flat layout, sorted by severity
    const allDetails = [...criticalDetails, ...infoDetails];
    allDetails.forEach(d => {
        html += _renderDetailItem(d);
    });

    // Raw record with syntax highlighting
    if (check.record) {
        const highlighted = highlightRecord(check.record, check.name);
        html += `
            <div class="record-block">
                <span class="record-text">${highlighted}</span>
                <button class="copy-btn">Copy</button>
            </div>
        `;
    }

    // SPF execution trace
    if (check._spf_execution) {
        html += renderSpfExecution(check._spf_execution);
    }

    // Tree walk visualization (DMARC only)
    if (check._tree_walk) {
        html += renderTreeWalk(check._tree_walk);
    }

    // DMARC evaluation summary (after tree walk)
    if (check._dmarc_eval) {
        html += renderDmarcEvaluation(check._dmarc_eval);
    }

    // DMARC report delivery chain
    if (check._report_chain) {
        html += renderReportChain(check._report_chain);
    }

    // SPF include tree
    if (check._spf_tree) {
        html += renderSpfTree(check._spf_tree);
    }

    // Fix preview -- before/after DNS records
    if (check.fix_records && check.fix_records.length > 0) {
        html += renderFixPreview(check.fix_records);
    }

    if (!html) {
        html = '<div class="explanation">No issues detected.</div>';
    }

    return html;
}

// ============================================================
// Fix Preview -- before/after DNS records
// ============================================================

function renderFixPreview(fixRecords) {
    let html = '<div class="fix-preview">';
    html += '<div class="fix-preview-label">Suggested Record</div>';

    for (const fr of fixRecords) {
        const value = fr.value || fr.suggested || '';
        if (!value) continue;

        html += '<div class="fix-preview-item">';
        html += `<div class="fix-preview-host">${escapeHtml(fr.type)} record at <strong>${escapeHtml(fr.host)}</strong></div>`;
        html += `<div class="fix-record-block">
            <span class="fix-record-value">${escapeHtml(value)}</span>
            <button class="copy-btn">Copy</button>
        </div>`;
        if (fr.comment) {
            html += `<div class="fix-comment">${escapeHtml(fr.comment)}</div>`;
        }
        html += '</div>';
    }

    html += '</div>';
    return html;
}

// ============================================================
// Tree Walk Visualization
// ============================================================

function renderTreeWalk(tw) {
    if (!tw || !tw.steps || tw.steps.length === 0) return '';

    // Simple mode: domain has its own DMARC record (1 step, found at author domain)
    const isSimple = tw.steps.length === 1 && tw.steps[0].found && !tw.is_subdomain;
    return isSimple ? renderTreeWalkSimple(tw) : renderTreeWalkFull(tw);
}

function renderTreeWalkSimple(tw) {
    const domain = escapeHtml(tw.domain);
    const policy = escapeHtml(tw.effective_policy || 'none');
    const policyClass = policy === 'reject' ? 'tw-pill-pass'
                      : policy === 'quarantine' ? 'tw-pill-warn'
                      : 'tw-pill-muted';

    return `
        <div class="tree-walk tree-walk-simple tw-animated">
            <div class="tw-header-row">
                <div class="tree-walk-header">DMARC Policy Discovery (Tree Walk)</div>
                <a class="tw-spec-badge" href="https://datatracker.ietf.org/doc/html/rfc9716"
                   target="_blank" rel="noopener">RFC 9716</a>
            </div>
            <div class="tw-simple-body">
                <span class="tw-simple-check">&#10003;</span>
                <span><strong>${domain}</strong> publishes its own DMARC record. No policy inheritance needed.</span>
            </div>
            <div class="tw-simple-policy">
                Policy: <span class="tw-pill ${policyClass}">${policy}</span>
            </div>
            <div class="tw-footnote">
                Under <a href="https://datatracker.ietf.org/doc/html/rfc9716" target="_blank" rel="noopener">RFC 9716</a>,
                receivers walk up the DNS hierarchy to find an applicable DMARC policy when a domain lacks its own record.
                This domain has a direct record, so the walk is not needed.
            </div>
        </div>`;
}

function renderTreeWalkFull(tw) {
    const specUrl = 'https://datatracker.ietf.org/doc/html/rfc9716';
    const stepCount = tw.steps.length;
    // Each step lands 150ms after the previous; metadata appears after the last step
    const stepInterval = 0.15;            // seconds between steps
    const lastStepLands = 0.05 + (stepCount - 1) * stepInterval + 0.35; // delay + anim duration
    const metaDelay = (lastStepLands + 0.1).toFixed(2);

    let html = `
        <div class="tree-walk tw-animated">
            <div class="tw-header-row">
                <div class="tree-walk-header">DMARC Policy Discovery (Tree Walk)</div>
                <a class="tw-spec-badge" href="${specUrl}" target="_blank" rel="noopener">RFC 9716</a>
            </div>`;

    // Educational intro
    if (!tw.policy_source) {
        html += `<div class="tw-intro">This domain does not have its own DMARC record.
            Under <a href="${specUrl}" target="_blank" rel="noopener">RFC 9716</a>,
            receivers walk up the DNS hierarchy looking for an applicable policy.
            <strong>No policy was found.</strong></div>`;
    } else if (tw.is_subdomain) {
        html += `<div class="tw-intro">This domain does not have its own DMARC record.
            Under <a href="${specUrl}" target="_blank" rel="noopener">RFC 9716</a>,
            receivers walk up the DNS hierarchy to find an applicable policy.</div>`;
    }

    // Timeline steps  --  pre-scan to find policy source index for line coloring
    const policyIdx = tw.steps.findIndex((s, i) =>
        s.found && tw.policy_source && s.domain === tw.policy_source && tw.is_subdomain);

    html += '<div class="tree-walk-steps">';
    tw.steps.forEach((step, i) => {
        const isLast = i === tw.steps.length - 1;
        const isPolicySource = step.found && tw.policy_source &&
            step.domain === tw.policy_source && tw.is_subdomain;
        const statusClass = step.found ? 'tw-found' : 'tw-notfound';
        const sourceClass = isPolicySource ? 'tw-policy-source' : '';
        const connector = isLast ? 'tw-last' : '';
        // Line on the step before the policy source turns green (leads into it)
        const lineColor = (policyIdx > 0 && i === policyIdx - 1) ? 'tw-line-to-found' : '';

        const stepDelay = (0.05 + i * stepInterval).toFixed(2);
        const lineDelay = (0.05 + i * stepInterval + 0.13).toFixed(2);

        html += `<div class="tw-step ${statusClass} ${sourceClass} ${lineColor} ${connector}" style="animation-delay:${stepDelay}s">`;
        html += `<div class="tw-connector" style="--line-delay:${lineDelay}s"><div class="tw-dot"></div></div>`;
        html += `<div class="tw-content">`;
        html += `<div class="tw-domain">${escapeHtml(step.query || '_dmarc.' + step.domain)}</div>`;
        html += `<div class="tw-label">${escapeHtml(step.label)}`;
        if (isPolicySource) html += ` <span class="tw-source-badge">policy source</span>`;
        if (step.stop_reason) html += ` &middot; stopped (${escapeHtml(step.stop_reason)})`;
        html += `</div>`;
        if (step.found && step.record) {
            html += `<div class="tw-record">${escapeHtml(step.record)}</div>`;
        } else {
            html += `<div class="tw-norecord">No DMARC record</div>`;
        }
        html += `</div></div>`;
    });
    html += '</div>';

    // Metadata summary
    if (tw.policy_source) {
        const policy = escapeHtml(tw.effective_policy || 'none');
        const policyClass = policy === 'reject' ? 'tw-pill-pass'
                          : policy === 'quarantine' ? 'tw-pill-warn'
                          : 'tw-pill-muted';
        const tag = tw.applied_tag || 'p';
        const tagExplanation = getTagExplanation(tag, tw);

        html += `<div class="tw-meta" style="animation-delay:${metaDelay}s">`;

        if (tw.org_domain) {
            html += `<div class="tw-meta-row">
                <span class="tw-meta-label">Organizational Domain</span>
                <span class="tw-meta-value"><code>${escapeHtml(tw.org_domain)}</code></span>
            </div>`;
        }

        html += `<div class="tw-meta-row">
            <span class="tw-meta-label">Effective Policy</span>
            <span class="tw-meta-value"><span class="tw-pill ${policyClass}">${policy}</span>
                from <strong>${escapeHtml(tw.policy_source)}</strong></span>
        </div>`;

        html += `<div class="tw-meta-row">
            <span class="tw-meta-label">Applied Tag</span>
            <span class="tw-meta-value"><code>${escapeHtml(tag)}</code>: ${tagExplanation}</span>
        </div>`;

        const walkQueries = tw.query_count != null ? tw.query_count : (tw.steps.length - 1);
        html += `<div class="tw-meta-row">
            <span class="tw-meta-label">Walk Queries</span>
            <span class="tw-meta-value">${walkQueries} of 8 max</span>
        </div>`;

        html += `</div>`;

        // Adoption note for inherited policies
        if (tw.is_subdomain) {
            html += `<div class="tw-footnote" style="animation-delay:${metaDelay}s">
                <strong>Note:</strong> Policy inheritance via tree walk is a
                <a href="https://datatracker.ietf.org/doc/html/rfc9716" target="_blank" rel="noopener">RFC 9716</a>
                feature. Receivers still using RFC 7489 may not honor the inherited policy.
                For the strongest protection, publish a dedicated DMARC record for this domain.
            </div>`;
        }
    } else {
        html += `<div class="tw-summary tw-no-policy" style="animation-delay:${metaDelay}s">No DMARC policy found in the DNS hierarchy.</div>`;
    }

    html += '</div>';
    return html;
}

function getTagExplanation(tag, tw) {
    switch (tag) {
        case 'sp':
            return 'the parent domain\'s <code>sp</code> (subdomain policy), which it explicitly set for subdomains';
        case 'np':
            return 'the parent domain\'s <code>np</code> (non-existent subdomain policy), because this domain does not exist in DNS';
        case 'p':
            if (tw.is_subdomain) {
                return 'the parent domain\'s <code>p</code> (domain policy), used as fallback because no <code>sp</code> tag was set';
            }
            return 'this domain\'s own <code>p</code> (domain policy)';
        default:
            return `<code>${escapeHtml(tag)}</code>`;
    }
}

// ============================================================
// SPF Execution Trace
// ============================================================

function renderSpfExecution(exec) {
    if (!exec || !exec.flat_steps || exec.flat_steps.length === 0) return '';

    const stepInterval = 0.15;
    const stepCount = exec.flat_steps.length;
    const lastStepLands = 0.05 + (stepCount - 1) * stepInterval + 0.35;
    const metaDelay = (lastStepLands + 0.1).toFixed(2);

    let html = `
        <div class="spf-execution se-animated">
            <div class="se-header-row">
                <div class="se-header">SPF Evaluation Trace</div>
                <a class="tw-spec-badge" href="https://datatracker.ietf.org/doc/html/rfc7208"
                   target="_blank" rel="noopener">rfc7208</a>
            </div>`;

    // Intro
    if (exec.over_limit) {
        html += `<div class="se-intro">This domain's SPF record requires <strong>${exec.total_lookups} DNS lookups</strong>,
            exceeding the RFC 7208 limit of 10. Receivers that enforce this limit will return a permanent error.</div>`;
    }

    // Timeline steps
    html += '<div class="se-steps">';
    exec.flat_steps.forEach((step, i) => {
        const isLast = i === exec.flat_steps.length - 1;
        const statusClass = step.status === 'exceeded' ? 'se-exceeded' : 'se-ok';
        const connector = isLast ? 'se-last' : '';
        const depthClass = `se-depth-${Math.min(step.depth, 3)}`;
        const stepDelay = (0.05 + i * stepInterval).toFixed(2);
        const lineDelay = (0.05 + i * stepInterval + 0.13).toFixed(2);

        html += `<div class="se-step ${statusClass} ${connector} ${depthClass}" style="animation-delay:${stepDelay}s">`;
        html += `<div class="se-connector" style="--line-delay:${lineDelay}s"><div class="se-dot"></div></div>`;
        html += `<div class="se-content">`;

        // Mechanism name
        html += `<span class="se-mechanism">${escapeHtml(step.mechanism)}</span>`;

        // Vendor badge (only for top-level includes with a match)
        if (step.vendor) {
            const catClass = step.vendor_category ? `se-vendor-${step.vendor_category}` : '';
            html += ` <span class="se-vendor-badge ${catClass}">${escapeHtml(step.vendor)}</span>`;
        }

        // Lookup counter pill
        if (step.lookup_range) {
            const counterClass = step.status === 'exceeded' ? 'se-counter exceeded' : 'se-counter';
            const label = step.lookup_range.includes('-')
                ? `lookups ${step.lookup_range}`
                : `lookup ${step.lookup_range}`;
            html += ` <span class="${counterClass}">${label}</span>`;
        }

        html += `</div></div>`;
    });
    html += '</div>';

    // Summary footer
    const totalClass = exec.over_limit ? 'se-counter exceeded' : 'se-counter';
    html += `<div class="se-footer" style="animation-delay:${metaDelay}s">
        Total: <span class="${totalClass}">${exec.total_lookups} / ${exec.limit} lookups</span>
    </div>`;

    html += '</div>';
    return html;
}

// ============================================================
// DMARC Evaluation Summary
// ============================================================

function renderDmarcEvaluation(ev) {
    if (!ev) return '';

    const spfPillClass = ev.spf_result === 'pass' ? 'de-pill-pass'
                       : ev.spf_result === 'none' ? 'de-pill-muted'
                       : 'de-pill-fail';
    const dkimPillClass = ev.dkim_result === 'pass' ? 'de-pill-pass'
                        : ev.dkim_result === 'none' ? 'de-pill-muted'
                        : 'de-pill-fail';
    const dmarcPillClass = ev.dmarc_result === 'pass' ? 'de-pill-pass' : 'de-pill-fail';
    const policyPillClass = ev.policy === 'reject' ? 'de-pill-pass'
                          : ev.policy === 'quarantine' ? 'de-pill-warn'
                          : 'de-pill-muted';

    const spfAlignIcon = ev.spf_aligned ? '&#10003; aligned' : '&#10005; not aligned';
    const spfAlignClass = ev.spf_aligned ? 'de-aligned' : 'de-not-aligned';
    const dkimAlignIcon = ev.dkim_aligned ? '&#10003; aligned' : '&#10005; not aligned';
    const dkimAlignClass = ev.dkim_aligned ? 'de-aligned' : 'de-not-aligned';

    const dispLabel = ev.disposition === 'none' ? 'delivered'
                    : ev.disposition === 'quarantine' ? 'quarantined'
                    : ev.disposition === 'reject' ? 'rejected'
                    : ev.disposition;

    return `
        <div class="dmarc-eval de-animated">
            <div class="se-header-row">
                <div class="se-header">DMARC Evaluation</div>
                <a class="tw-spec-badge" href="https://datatracker.ietf.org/doc/html/rfc7489"
                   target="_blank" rel="noopener">rfc7489</a>
            </div>
            <div class="de-intro">${escapeHtml(ev.explanation)}</div>
            <div class="de-rows">
                <div class="de-row">
                    <span class="de-protocol">SPF</span>
                    <span class="de-pill ${spfPillClass}">${ev.spf_result}</span>
                    <span class="de-align-mode">${ev.spf_alignment_mode}</span>
                    <span class="de-align-result ${spfAlignClass}">${spfAlignIcon}</span>
                </div>
                <div class="de-row">
                    <span class="de-protocol">DKIM</span>
                    <span class="de-pill ${dkimPillClass}">${ev.dkim_result}</span>
                    <span class="de-align-mode">${ev.dkim_alignment_mode}</span>
                    <span class="de-align-result ${dkimAlignClass}">${dkimAlignIcon}</span>
                </div>
                <div class="de-row de-final">
                    <span class="de-protocol">DMARC</span>
                    <span class="de-pill ${dmarcPillClass}">${ev.dmarc_result}</span>
                    <span class="de-policy-group">
                        policy: <span class="de-pill ${policyPillClass}">${escapeHtml(ev.policy)}</span>
                    </span>
                    <span class="de-disposition">${escapeHtml(dispLabel)}</span>
                </div>
            </div>
        </div>`;
}

// ============================================================
// DMARC Report Delivery Chain
// ============================================================

function renderReportChain(rc) {
    if (!rc || !rc.report_destinations || rc.report_destinations.length === 0) return '';

    const dests = rc.report_destinations;
    const hasUnauthorized = dests.some(d => d.authorized === false);
    const introClass = hasUnauthorized ? 'rc-intro rc-intro-warn' : 'rc-intro';
    const introText = hasUnauthorized
        ? 'One or more external report destinations are not authorized. Reports to those addresses will be silently dropped.'
        : 'All report destinations are properly configured to receive DMARC reports.';

    let html = `
        <div class="report-chain rc-animated">
            <div class="se-header-row">
                <div class="se-header">DMARC Report Delivery Chain</div>
                <a class="tw-spec-badge" href="https://datatracker.ietf.org/doc/html/rfc7489#section-7.1"
                   target="_blank" rel="noopener">rfc7489 &sect;7.1</a>
            </div>
            <div class="${introClass}">${escapeHtml(introText)}</div>
            <div class="rc-dests">`;

    dests.forEach((dest, i) => {
        const delay = (0.05 + i * 0.12).toFixed(2);
        const typeClass = dest.type === 'rua' ? 'rc-type-rua' : 'rc-type-ruf';

        let authHtml = '';
        if (dest.authorized === true) {
            authHtml = '<span class="rc-auth rc-authorized">&#10003; External authorization verified</span>';
        } else if (dest.authorized === false) {
            authHtml = '<span class="rc-auth rc-unauthorized">&#10005; Not authorized (reports will be dropped)</span>';
        } else {
            authHtml = '<span class="rc-auth rc-same-domain">&#10003; Same domain (no external authorization needed)</span>';
        }

        let mxHtml = '';
        if (dest.has_mx === true) {
            mxHtml = '<span class="rc-mx-ok">Can receive mail &#10003;</span>';
        } else if (dest.has_mx === false && dest.is_external) {
            mxHtml = '<span class="rc-mx-fail">Cannot receive mail (no MX)</span>';
        }

        let serviceHtml = '';
        if (dest.service) {
            serviceHtml = `<span class="se-vendor-badge se-vendor-email_security">${escapeHtml(dest.service)}</span>`;
        }

        html += `
            <div class="rc-dest" style="animation-delay:${delay}s">
                <span class="rc-type ${typeClass}">${dest.type === 'rua' ? 'Aggregate reports' : 'Failure reports'}</span>
                <span class="rc-address">${escapeHtml(dest.address)}</span>
                ${serviceHtml}
                ${authHtml}
                ${mxHtml}
            </div>`;
    });

    html += '</div>';

    if (rc.ruf_provider_note) {
        html += `<div class="rc-footnote">Note: Most major mailbox providers (Google, Microsoft, Yahoo) no longer send failure reports (ruf) because they can contain PII (message headers, recipient addresses).</div>`;
    }

    html += '</div>';
    return html;
}

// ============================================================
// SPF Include Tree
// ============================================================

function renderSpfTree(tree) {
    if (!tree || !tree.root) return '';

    const used = tree.total_lookups;
    const limit = tree.limit || 10;
    const pct = Math.min((used / limit) * 100, 100);
    const barClass = used > limit ? 'st-bar-over' : used >= 8 ? 'st-bar-warn' : 'st-bar-ok';
    const statusLabel = used > limit ? 'OVER LIMIT' : used >= 8 ? 'NEAR LIMIT' : '';

    let html = `
        <div class="spf-tree st-animated">
            <div class="se-header-row">
                <div class="se-header">SPF Lookup Budget</div>
                <a class="tw-spec-badge" href="https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4"
                   target="_blank" rel="noopener">RFC 7208 &sect;4.6.4</a>
            </div>
            <div class="st-budget">
                <div class="st-budget-label">
                    <span><strong>${used}</strong> of <strong>${limit}</strong> DNS lookups used</span>
                    ${statusLabel ? `<span class="st-budget-status ${barClass}">${statusLabel}</span>` : ''}
                </div>
                <div class="st-budget-track">
                    <div class="st-budget-fill ${barClass}" style="width:${pct}%"></div>
                </div>
                <div class="st-budget-note">RFC 7208 limits SPF to 10 DNS-querying mechanisms (include, a, mx, redirect, exists). Exceeding this causes a PermError.</div>
            </div>
            <div class="st-tree-label">Include hierarchy: each include costs 1 lookup plus any nested lookups</div>`;

    html += renderTreeNode(tree.root, tree.total_lookups, true);

    html += '</div>';
    return html;
}

function renderTreeNode(node, totalLookups, isRoot) {
    if (!node) return '';

    const openAttr = isRoot ? ' open' : '';
    const budgetPct = totalLookups > 0 ? Math.round((node.subtree_lookups / totalLookups) * 100) : 0;
    const costClass = budgetPct > 60 ? 'st-budget-high'
                    : budgetPct > 30 ? 'st-budget-mid'
                    : 'st-budget-low';

    let vendorHtml = '';
    if (node.vendor) {
        const catClass = node.vendor_category ? `se-vendor-${node.vendor_category}` : '';
        vendorHtml = `<span class="se-vendor-badge ${catClass}">${escapeHtml(node.vendor)}</span>`;
    }

    // Lookup cost -- prominent, before domain name
    let costHtml = '';
    if (isRoot) {
        // Root shows total
        costHtml = `<span class="st-cost st-cost-root">${node.lookups_here} direct</span>`;
    } else if (node.subtree_lookups > 0) {
        costHtml = `<span class="st-cost ${costClass}">${node.subtree_lookups + 1} lookup${node.subtree_lookups > 0 ? 's' : ''}</span>`;
    } else {
        costHtml = '<span class="st-cost st-cost-leaf">1 lookup</span>';
    }

    let html = `<details class="st-node"${openAttr}>`;
    html += `<summary>${costHtml} <span class="st-domain">${escapeHtml(node.domain)}</span> ${vendorHtml}</summary>`;

    // Record
    if (node.record) {
        html += `<div class="st-record">${escapeHtml(node.record)}</div>`;
    }

    // IPs
    if (node.ips && node.ips.length > 0) {
        html += '<div class="st-ips">';
        node.ips.forEach(ip => {
            html += `<span class="st-ip">${escapeHtml(ip)}</span>`;
        });
        html += '</div>';
    }

    // Children
    if (node.children && node.children.length > 0) {
        html += '<div class="st-children">';
        node.children.forEach(child => {
            html += renderTreeNode(child, totalLookups, false);
        });
        html += '</div>';
    }

    // Terminal
    if (node.terminal && isRoot) {
        html += `<div class="st-terminal">${escapeHtml(node.terminal)}</div>`;
    }

    html += '</details>';
    return html;
}

// ============================================================
// Export JSON
// ============================================================

document.getElementById('export-btn').addEventListener('click', () => {
    if (!lastAuditData) return;
    const blob = new Blob([JSON.stringify(lastAuditData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dns-audit-${lastAuditData.domain || 'report'}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
});

// ============================================================
// PDF Report Download
// ============================================================

document.getElementById('pdf-btn').addEventListener('click', () => {
    if (!lastAuditData) return;
    const btn = document.getElementById('pdf-btn');
    const span = btn.querySelector('span');
    const origText = span.textContent;
    span.textContent = 'Generating...';
    btn.disabled = true;

    const url = `${API_BASE}/audit/pdf?domain=${encodeURIComponent(lastAuditData.domain)}`;
    fetch(url)
        .then(resp => {
            if (!resp.ok) throw new Error(`PDF generation failed (${resp.status})`);
            return resp.blob();
        })
        .then(blob => {
            const blobUrl = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = blobUrl;
            a.download = `dns-audit-${lastAuditData.domain}.pdf`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(blobUrl);
            span.textContent = origText;
            btn.disabled = false;
        })
        .catch(err => {
            console.error('PDF error:', err);
            span.textContent = 'Failed';
            btn.disabled = false;
            setTimeout(() => { span.textContent = origText; }, 2000);
        });
});

// ============================================================
// Expand All / Collapse All
// ============================================================

(() => {
    const toggleBtn = document.getElementById('toggle-all-btn');
    let allExpanded = false;

    toggleBtn.addEventListener('click', () => {
        // Sync state with actual DOM before toggling
        const cards = document.querySelectorAll('.result-card');
        const expandedCount = document.querySelectorAll('.result-card.expanded').length;
        allExpanded = expandedCount > cards.length / 2;
        allExpanded = !allExpanded;
        cards.forEach(card => {
            card.classList.toggle('expanded', allExpanded);
        });
        toggleBtn.querySelector('span').textContent = allExpanded ? 'Collapse All' : 'Expand All';
    });
})();

// ============================================================
// Helpers
// ============================================================

function _copyToClipboard(text, feedbackEl, origLabel) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            if (feedbackEl) { feedbackEl.textContent = 'Copied!'; setTimeout(() => feedbackEl.textContent = origLabel, 2000); }
        }).catch(() => _copyFallback(text, feedbackEl, origLabel));
    } else {
        _copyFallback(text, feedbackEl, origLabel);
    }
}

function _copyFallback(text, feedbackEl, origLabel) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
        document.execCommand('copy');
        if (feedbackEl) { feedbackEl.textContent = 'Copied!'; setTimeout(() => feedbackEl.textContent = origLabel, 2000); }
    } catch {
        if (feedbackEl) { feedbackEl.textContent = 'Failed'; setTimeout(() => feedbackEl.textContent = origLabel, 2000); }
    }
    document.body.removeChild(ta);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Sanitize trusted HTML from the backend (fix/explanation fields).
 * Only allows a whitelist of safe tags; strips everything else.
 */
function sanitizeHtml(html) {
    if (!html) return '';
    const ALLOWED_TAGS = ['strong', 'em', 'code', 'br', 'b', 'i', 'a'];
    const ALLOWED_LINK_ATTRS = ['href', 'target', 'rel'];
    const tmp = document.createElement('div');
    tmp.innerHTML = html;

    function clean(node) {
        const children = Array.from(node.childNodes);
        for (const child of children) {
            if (child.nodeType === Node.ELEMENT_NODE) {
                const tag = child.tagName.toLowerCase();
                if (!ALLOWED_TAGS.includes(tag)) {
                    // Replace disallowed element with its text content
                    const text = document.createTextNode(child.textContent);
                    node.replaceChild(text, child);
                } else {
                    // Strip all attributes; for <a> keep only the safe link attrs
                    const attrsToRemove = Array.from(child.attributes)
                        .map(a => a.name)
                        .filter(name => tag !== 'a' || !ALLOWED_LINK_ATTRS.includes(name));
                    for (const name of attrsToRemove) {
                        child.removeAttribute(name);
                    }
                    // Block non-http(s) protocols on links (XSS prevention)
                    if (tag === 'a') {
                        const href = child.getAttribute('href') || '';
                        if (href && !/^https?:\/\//i.test(href)) {
                            child.removeAttribute('href');
                        }
                    }
                    clean(child);
                }
            }
        }
    }

    clean(tmp);
    return tmp.innerHTML;
}

