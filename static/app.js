/* ==========================================================================
   DNS Security Auditor - Frontend Application
   v2.0  --  Scoped audits, severity sorting, auto-collapse
   ========================================================================== */

const API_BASE = '/api';

// -- Scope definitions: which checks to show per scope --
const SCOPE_CHECKS = {
    complete: null, // null = show all
    email_full: ['DMARC', 'SPF', 'DKIM', 'MX Records', 'MX', 'MTA-STS', 'TLS-RPT', 'BIMI', 'Blocklist'],
    dmarc: ['DMARC', 'SPF', 'DKIM'],
    transport: ['MTA-STS', 'TLS-RPT', 'DANE', 'MX Records', 'MX'],
    dns_infra: ['DNSSEC', 'CAA', 'DANE', 'Nameservers', 'Certificate Transparency'],
    security_scan: ['DMARC', 'SPF', 'DKIM', 'DNSSEC', 'DANE', 'Certificate Transparency', 'Blocklist', 'CAA', 'MTA-STS'],
};

// Severity sort order (lower = higher priority = displayed first)
const SEVERITY_ORDER = { fail: 0, warn: 1, pass: 2 };

const DEFAULT_TITLE = document.title;
let currentScope = 'complete';
let lastAuditData = null;
let auditStartTime = 0;
let auditController = null;

// -- DOM References --
const auditForm = document.getElementById('audit-form');
const domainInput = document.getElementById('domain-input');
const auditBtn = document.getElementById('audit-btn');
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

// -- Protocol tooltip descriptions --
const PROTOCOL_TOOLTIPS = {
    'DMARC': 'Tells receivers what to do with unauthenticated email from your domain',
    'SPF': 'Lists which servers are authorized to send email for your domain',
    'DKIM': 'Cryptographic signature proving emails haven\'t been tampered with',
    'BIMI': 'Displays your brand logo in email clients that support it',
    'MTA-STS': 'Forces encrypted TLS connections between mail servers',
    'TLS-RPT': 'Receives reports when TLS connections to your domain fail',
    'DANE': 'Uses DNSSEC to verify mail server TLS certificates',
    'DNSSEC': 'Cryptographically signs DNS records to prevent spoofing',
    'CAA': 'Controls which Certificate Authorities can issue certificates for your domain',
    'MX Records': 'Specifies which mail servers accept email for your domain',
    'MX': 'Specifies which mail servers accept email for your domain',
    'Nameservers': 'The DNS servers that answer queries about your domain',
    'Certificate Transparency': 'Public log of all certificates issued for your domain',
    'Blocklist': 'Checks if your domain or IPs appear on email blocklists',
};

// -- Check URL for domain parameter on load --
document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const domain = params.get('d');
    const scope = params.get('scope');
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

    // Back-to-top button
    const backToTop = document.createElement('button');
    backToTop.innerHTML = '\u2191';
    backToTop.className = 'back-to-top';
    backToTop.setAttribute('aria-label', 'Back to top');
    document.body.appendChild(backToTop);
    backToTop.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });
    window.addEventListener('scroll', () => {
        backToTop.classList.toggle('visible', window.scrollY > 500);
    }, { passive: true });
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
    // Abort any in-flight audit request
    if (auditController) auditController.abort();
    auditController = new AbortController();
    const signal = auditController.signal;

    auditStartTime = performance.now();
    document.title = `Scanning ${domain}...`;
    showLoading();
    hideResults();

    const selectorVal = document.getElementById('selector-input')?.value?.trim() || '';
    let streamUrl = `${API_BASE}/audit/stream?domain=${encodeURIComponent(domain)}`;
    if (selectorVal) streamUrl += `&selector=${encodeURIComponent(selectorVal)}`;
    if (currentScope && currentScope !== 'complete') streamUrl += `&scope=${encodeURIComponent(currentScope)}`;

    try {
        const resp = await fetch(streamUrl, { signal });
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
        if (err.name === 'AbortError') return;
        console.error('SSE audit error:', err);
        // Fall back to the regular JSON endpoint
        try {
            let auditUrl = `${API_BASE}/audit?domain=${encodeURIComponent(domain)}`;
            if (selectorVal) auditUrl += `&selector=${encodeURIComponent(selectorVal)}`;
            if (currentScope && currentScope !== 'complete') auditUrl += `&scope=${encodeURIComponent(currentScope)}`;
            const resp = await fetch(auditUrl, { signal });
            if (!resp.ok) {
                const fallbackErr = await resp.json().catch(() => ({}));
                throw new Error(fallbackErr.detail || `Audit failed (HTTP ${resp.status})`);
            }
            const data = await resp.json();
            renderResults(data);
        } catch (fallbackErr) {
            if (fallbackErr.name === 'AbortError') return;
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
    'Tree Walk': 'Resolving DNS records...',
    'DMARC': 'Checking DMARC policy...',
    'MX': 'Checking MX records...',
    'SPF': 'Analyzing SPF configuration...',
    'MTA-STS': 'Validating MTA-STS...',
    'TLS-RPT': 'Checking TLS-RPT...',
    'BIMI': 'Looking for BIMI record...',
    'DNSSEC': 'Verifying DNSSEC chain...',
    'CAA': 'Checking CAA records...',
    'Nameservers': 'Checking nameservers...',
    'DANE': 'Checking DANE TLSA records...',
    'DKIM': 'Discovering DKIM selectors...',
    'Certificate Transparency': 'Querying certificate transparency logs...',
    'Blocklist': 'Checking IP and domain blocklists...',
    'Vendor Fingerprinting': 'Fingerprinting email services...',
    'Scoring': 'Calculating security score...',
};

function showLoading() {
    // Compact the input section so the progress bar is above the fold
    document.querySelector('.audit-input-section')?.classList.add('compact');

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

    // Top progress bar
    let topBar = document.querySelector('.top-progress-bar');
    if (!topBar) {
        topBar = document.createElement('div');
        topBar.className = 'top-progress-bar';
        document.body.appendChild(topBar);
    }
    topBar.classList.remove('complete');
    topBar.style.width = '0%';
    topBar.style.opacity = '1';

    // Scroll so the loading bar is visible
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function updateLoadingProgress(step, progressPct) {
    const bar = document.getElementById('loading-bar');
    const status = document.getElementById('loading-status');
    const pct = Math.min(progressPct, 97);
    if (bar) bar.style.width = pct + '%';
    if (status) status.textContent = STEP_MESSAGES[step] || `Checking ${step}...`;
    const topBar = document.querySelector('.top-progress-bar');
    if (topBar) topBar.style.width = pct + '%';
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

    // Handle preflight / server errors returned inside the result object
    if (data.error && data.error_message) {
        hideLoading();
        showError(data.error_message);
        return;
    }

    // Finish loading animation
    const bar = document.getElementById('loading-bar');
    const status = document.getElementById('loading-status');
    if (bar) bar.style.width = '100%';
    if (status) status.textContent = 'Complete';
    const topBar = document.querySelector('.top-progress-bar');
    if (topBar) topBar.classList.add('complete');

    const scopeAtRender = currentScope;
    setTimeout(() => {
        hideLoading();
        resultsSection.style.display = 'block';

        // Compact the input section so results are visible above the fold
        document.querySelector('.audit-input-section')?.classList.add('compact');

        // Scroll to top of results
        const yOffset = -10;
        const y = resultsSection.getBoundingClientRect().top + window.pageYOffset + yOffset;
        window.scrollTo({ top: y, behavior: 'smooth' });

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
    const gradeEl = document.getElementById('summary-grade');
    const grade = data.score?.grade || '--';
    const isDefensive = data.defensive_dns;

    // Clear previous animation classes
    gradeEl.classList.remove('animate-in', 'grade-glow');

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
            'A+': { bg: '#ecfdf5', border: '#059669', text: '#064e3b' },
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
        // Grade entrance animation (with glow for A/A+)
        if (grade === 'A' || grade === 'A+') {
            gradeEl.classList.add('grade-glow');
        } else {
            gradeEl.classList.add('animate-in');
        }
    }
    // Score number with count-up animation
    const scoreNum = data.score?.total;
    let scoreEl = document.getElementById('summary-score');
    if (scoreNum !== undefined && gradeCard) {
        if (!scoreEl) {
            scoreEl = document.createElement('div');
            scoreEl.id = 'summary-score';
            scoreEl.className = 'score-subtext';
            gradeEl.parentNode.insertBefore(scoreEl, gradeEl.nextSibling);
        }
        _animateScore(scoreEl, Math.round(scoreNum));
    } else if (scoreEl) {
        scoreEl.remove();
    }

    // -- Authentication Resilience --
    const resSection = document.getElementById('resilience-section');
    const res = data.resilience;
    if (res) {
        resSection.style.display = 'block';
        const levelColors = { high: 'pass', moderate: 'warn', low: 'fail', none: 'fail' };
        const levelClass = levelColors[res.level] || 'info';

        document.getElementById('resilience-summary').innerHTML = `
            <span class="resilience-level resilience-${levelClass}">${res.level.toUpperCase()}</span>
            <span class="resilience-text">${escapeHtml(res.summary)}</span>
        `;

        const mechs = res.mechanisms || {};
        let mechHtml = '';
        for (const [name, info] of Object.entries(mechs)) {
            const sClass = info.status === 'missing' || info.status === 'broken' ? 'fail'
                : info.status === 'not_detected' || info.status === 'none' ? 'warn' : 'pass';
            mechHtml += `<div class="resilience-mech">
                <span class="resilience-mech-name">${escapeHtml(name.toUpperCase())}</span>
                <span class="resilience-mech-status resilience-${sClass}">${escapeHtml(info.status)}</span>
                ${info.note ? `<span class="resilience-mech-note">${escapeHtml(info.note)}</span>` : ''}
            </div>`;
        }
        document.getElementById('resilience-mechanisms').innerHTML = mechHtml;

        if (res.risk) {
            document.getElementById('resilience-risk').innerHTML = `<div class="resilience-risk-text">${escapeHtml(res.risk)}</div>`;
        }
    } else {
        resSection.style.display = 'none';
    }

    // -- Priority fixes (always at top, before detailed results) --
    const prioritySection = document.getElementById('priority-section');
    const priorityList = document.getElementById('priority-list');
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
            const sevClass = { critical: 'fail', high: 'warn', medium: 'info' }[a.severity] || 'info';
            const sevLabel = { critical: 'Critical', high: 'High', medium: 'Medium' }[a.severity] || escapeHtml(a.severity);
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

    // Security Roadmap (Prompt 11) -- render at top of results
    if (data.security_roadmap && data.security_roadmap.items && data.security_roadmap.items.length > 0) {
        const roadmapEl = document.createElement('div');
        roadmapEl.innerHTML = renderSecurityRoadmap(data.security_roadmap);
        resultsList.appendChild(roadmapEl.firstElementChild);
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
    const vendorsGrid = document.getElementById('vendors-grid');
    vendorsGrid.innerHTML = '';

    if (data.vendors && data.vendors.length > 0) {
        vendorsSection.style.display = 'block';
        data.vendors.forEach(v => {
            const card = document.createElement('div');
            card.className = 'vendor-card';
            card.innerHTML = `
                <div class="vendor-name">${escapeHtml(v.name)}</div>
                <div class="vendor-confidence">Detected via DNS records</div>
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
    card.style.animationDelay = `${index * 60}ms`;

    const statusLabel = check.pill_label || {
        pass: 'Pass', warn: 'Warning', fail: 'Issue'
    }[check.status] || 'Unknown';

    const tooltipText = PROTOCOL_TOOLTIPS[check.name] || '';
    const titleHtml = tooltipText
        ? `<div class="result-title"><span class="protocol-name-tip" tabindex="0">${escapeHtml(check.name)}<span class="protocol-tooltip">${escapeHtml(tooltipText)}</span></span></div>`
        : `<div class="result-title">${escapeHtml(check.name)}</div>`;

    card.innerHTML = `
        <div class="result-header">
            <div class="status-dot ${check.status}"></div>
            ${titleHtml}
            <span class="status-pill ${check.status}">${escapeHtml(statusLabel)}</span>
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

    // Spec Mode Toggle (Prompt 5) — only for DMARC with both validations
    if (check.spec_comparison && check.strict_validation && check.legacy_validation) {
        html += renderSpecToggle(check.spec_comparison);
    }

    // DMARCbis Strict Validation (shown in DMARCbis mode)
    if (check.strict_validation) {
        html += `<div class="spec-dmarcbis">`;
        html += renderStrictValidation(check.strict_validation);
        html += `</div>`;
    }

    // Legacy Validation (hidden by default, shown in Legacy mode)
    if (check.legacy_validation) {
        html += `<div class="spec-legacy" style="display:none;">`;
        html += renderStrictValidation(check.legacy_validation);
        html += `</div>`;
    }

    // Structural errors banner for subsequent sections
    if (check.strict_validation && check.strict_validation.has_structural_errors) {
        html += `<div class="sv-error-banner spec-dmarcbis">Results below may be unreliable &mdash; this record has structural errors that affect parsing.</div>`;
    }

    // Attack Surface View (Prompt 6)
    if (check.attack_surface) {
        html += renderAttackSurface(check.attack_surface);
    }

    // DMARC Record Breakdown (DMARCbis mode only — has DMARCbis notes, health verdict, migration, etc.)
    if (check.tag_breakdown) {
        html += `<div class="spec-dmarcbis">`;
        html += renderDmarcTagBreakdown(check.tag_breakdown);
        html += `</div>`;
    }

    // SPF execution trace
    if (check._spf_execution) {
        html += renderSpfExecution(check._spf_execution);
    }

    // Tree walk visualization (DMARC only)
    if (check._tree_walk) {
        html += renderTreeWalk(check._tree_walk);
    }

    // DMARCbis readiness (after tree walk, before evaluation) — DMARCbis mode only
    if (check.dmarcbis_readiness) {
        html += `<div class="spec-dmarcbis">`;
        html += renderDmarcbisReadiness(check.dmarcbis_readiness);
        html += `</div>`;
    }

    // DMARC evaluation summary (after tree walk)
    if (check._dmarc_eval) {
        html += renderDmarcEvaluation(check._dmarc_eval);
    }

    // DMARC report delivery chain
    if (check._report_chain) {
        html += renderReportChain(check._report_chain);
    }

    // SPF Deep Analysis (Prompt 7)
    if (check.spf_deep) {
        html += renderSpfDeepAnalysis(check.spf_deep);
    }

    // DKIM Deep Analysis (Prompt 8)
    if (check.dkim_deep) {
        html += renderDkimKeyAnalysis(check.dkim_deep);
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
// Spec Mode Toggle (RFC 7489 vs DMARCbis)
// ============================================================

let _specMode = 'dmarcbis'; // session-persistent toggle state

function renderSpecToggle(comparison) {
    if (!comparison) return '';

    // "See the Future" callout
    let futureHtml = '';
    if (comparison.see_the_future && comparison.dmarcbis_only_items.length > 0) {
        let itemsHtml = comparison.dmarcbis_only_items.map(item =>
            `<div class="st-future-item">
                <span class="st-future-code">${escapeHtml(item.code)}</span>
                <span class="st-future-msg">${escapeHtml(item.message)}</span>
            </div>`
        ).join('');
        futureHtml = `
            <div class="st-future spec-dmarcbis">
                <div class="st-future-title">This record passes under RFC 7489 but has issues under DMARCbis</div>
                <div class="st-future-subtitle">${comparison.dmarcbis_only_count} problem${comparison.dmarcbis_only_count !== 1 ? 's' : ''} found that only appear under strict DMARCbis validation. Fixing these now ensures your record continues to work as receivers adopt the new standard.</div>
                ${itemsHtml}
            </div>`;
    }

    // Delta banner (switches with toggle)
    let deltaDmarcbis = '';
    if (comparison.dmarcbis_only_count > 0) {
        deltaDmarcbis = `<div class="st-delta spec-dmarcbis">DMARCbis strict validation found ${comparison.dmarcbis_only_count} additional issue${comparison.dmarcbis_only_count !== 1 ? 's' : ''} that legacy validation missed.</div>`;
    }
    let deltaLegacy = '';
    if (comparison.dmarcbis_only_count > 0) {
        deltaLegacy = `<div class="st-delta spec-legacy" style="display:none;">Legacy mode is more lenient. ${comparison.dmarcbis_only_count} issue${comparison.dmarcbis_only_count !== 1 ? 's' : ''} flagged by DMARCbis ${comparison.dmarcbis_only_count !== 1 ? 'are' : 'is'} accepted under RFC 7489.</div>`;
    }

    return `
        <div class="st-toggle-bar">
            <div class="st-toggle-label">Validation Mode</div>
            <div class="st-toggle-pills">
                <button class="st-pill st-pill-legacy" data-mode="legacy">RFC 7489 (Legacy)</button>
                <button class="st-pill st-pill-dmarcbis st-pill-active" data-mode="dmarcbis">DMARCbis (Strict)</button>
            </div>
        </div>
        ${deltaDmarcbis}
        ${deltaLegacy}
        ${futureHtml}`;
}

// Attach toggle handler via event delegation
document.addEventListener('click', function(e) {
    const pill = e.target.closest('.st-pill');
    if (!pill) return;

    const mode = pill.dataset.mode;
    if (mode === _specMode) return;
    _specMode = mode;

    // Update pill active states
    const bar = pill.closest('.st-toggle-bar');
    bar.querySelectorAll('.st-pill').forEach(p => p.classList.remove('st-pill-active'));
    pill.classList.add('st-pill-active');

    // Find the parent card
    const card = pill.closest('.result-card');
    if (!card) return;

    // Toggle visibility of spec-mode sections
    card.querySelectorAll('.spec-dmarcbis').forEach(el => {
        el.style.display = mode === 'dmarcbis' ? '' : 'none';
    });
    card.querySelectorAll('.spec-legacy').forEach(el => {
        el.style.display = mode === 'legacy' ? '' : 'none';
    });
});

// ============================================================
// Attack Surface View
// ============================================================

function renderAttackSurface(as) {
    if (!as || !as.vectors || as.vectors.length === 0) return '';

    const statusLabels = { protected: 'Protected', partial: 'Partially Protected', exposed: 'Exposed' };
    const statusIcons = { protected: '&#9632;', partial: '&#9650;', exposed: '&#9679;' };

    // Overall score
    const overallClass = `as-overall-${as.overall.color}`;

    // Vectors
    let vectorsHtml = '';
    as.vectors.forEach(v => {
        const statusLabel = statusLabels[v.status] || v.status;
        const icon = statusIcons[v.status] || '';
        vectorsHtml += `
            <div class="as-vector as-vector-${v.color}">
                <div class="as-vector-header">
                    <span class="as-vector-name">${escapeHtml(v.name)}</span>
                    <span class="as-vector-badge as-badge-${v.color}">${icon} ${escapeHtml(statusLabel)}</span>
                </div>
                <div class="as-vector-summary">${escapeHtml(v.summary)}</div>
                <div class="as-vector-detail">${escapeHtml(v.detail)}</div>
            </div>`;
    });

    // Attacker perspective
    let attackerHtml = '';
    if (as.attacker_path) {
        attackerHtml = `<div class="as-attacker">${escapeHtml(as.attacker_path)}</div>`;
    }

    return `
        <div class="as-block">
            <div class="as-header">
                <div class="as-header-left">
                    <span class="as-title">Email Spoofing Attack Surface</span>
                </div>
                <span class="as-overall ${overallClass}">${escapeHtml(as.overall.label)}</span>
            </div>
            <div class="as-overall-summary">${escapeHtml(as.overall.summary)}</div>
            ${attackerHtml}
            <div class="as-vectors">${vectorsHtml}</div>
        </div>`;
}

// ============================================================
// DMARCbis Strict Validation
// ============================================================

function renderStrictValidation(sv) {
    if (!sv || !sv.categories || sv.categories.length === 0) return '';

    const statusIcon = {
        pass: '<span class="sv-icon sv-pass">&#10003;</span>',
        fail: '<span class="sv-icon sv-fail">&#10005;</span>',
        warn: '<span class="sv-icon sv-warn">&#9651;</span>'
    };

    // Summary badge
    const summaryClass = sv.fail_count > 0 ? 'sv-summary-fail'
        : sv.warn_count > 0 ? 'sv-summary-warn' : 'sv-summary-pass';

    // Build category sections
    let categoriesHtml = '';
    sv.categories.forEach(cat => {
        let checksHtml = '';
        cat.checks.forEach(c => {
            const icon = statusIcon[c.status] || statusIcon.warn;
            checksHtml += `
                <div class="sv-check sv-check-${c.status}">
                    ${icon}
                    <span class="sv-check-msg">${escapeHtml(c.message)}</span>
                    <code class="sv-check-code">${escapeHtml(c.code)}</code>
                </div>`;
        });

        const catPass = cat.checks.filter(c => c.status === 'pass').length;
        const catTotal = cat.checks.length;
        const catClass = cat.checks.some(c => c.status === 'fail') ? 'sv-cat-fail'
            : cat.checks.some(c => c.status === 'warn') ? 'sv-cat-warn' : 'sv-cat-pass';

        categoriesHtml += `
            <div class="sv-category ${catClass}">
                <div class="sv-cat-header">
                    <span class="sv-cat-label">${escapeHtml(cat.label)}</span>
                    <span class="sv-cat-score">${catPass}/${catTotal}</span>
                </div>
                <div class="sv-checks">${checksHtml}</div>
            </div>`;
    });

    return `
        <div class="sv-block">
            <div class="sv-header">
                <div class="sv-header-left">
                    <span class="sv-badge">DMARCbis</span>
                    <span class="sv-title">Strict Record Validation</span>
                </div>
                <div class="sv-header-right">
                    <span class="sv-summary ${summaryClass}">${escapeHtml(sv.summary)}</span>
                    <span class="sv-score">${sv.pass_count}/${sv.total_count}</span>
                </div>
            </div>
            ${categoriesHtml}
        </div>`;
}

// ============================================================
// DMARC Record Breakdown
// ============================================================

function renderDmarcTagBreakdown(bd) {
    if (!bd || !bd.tags || bd.tags.length === 0) return '';

    // DMARCbis status badge classes
    const dmarcbisClasses = {
        'current': 'rb-bis-current',
        'deprecated': 'rb-bis-deprecated',
        'new': 'rb-bis-new'
    };
    const dmarcbisLabels = {
        'current': 'Current',
        'deprecated': 'Deprecated',
        'new': 'New in DMARCbis'
    };

    // Health verdict colors (5 states)
    const verdictClasses = {
        'ready': 'rb-verdict-ready',
        'compatible': 'rb-verdict-compatible',
        'monitoring': 'rb-verdict-monitoring',
        'attention': 'rb-verdict-attention',
        'misconfigured': 'rb-verdict-misconfigured'
    };

    // --- Health verdict header (Prompt 3) ---
    let verdictHtml = '';
    if (bd.health) {
        const h = bd.health;
        const cls = verdictClasses[h.status] || 'rb-verdict-attention';
        let reasonsHtml = '';
        if (h.reasons && h.reasons.length > 0) {
            reasonsHtml = h.reasons.map(r => `<span class="rb-verdict-reason">${escapeHtml(r)}</span>`).join('');
        }
        verdictHtml = `
            <div class="rb-verdict ${cls}">
                <div class="rb-verdict-top">
                    <span class="rb-verdict-label">${escapeHtml(h.label)}</span>
                    <span class="rb-verdict-summary">${escapeHtml(h.summary)}</span>
                </div>
                ${reasonsHtml ? `<div class="rb-verdict-reasons">${reasonsHtml}</div>` : ''}
            </div>`;
    }

    // --- Tag rows ---
    let tagsHtml = '';
    bd.tags.forEach(tag => {
        const bisClass = dmarcbisClasses[tag.dmarcbis] || '';
        const bisLabel = dmarcbisLabels[tag.dmarcbis] || '';

        // Value display
        let valueDisplay;
        if (tag.is_absent && tag.value == null) {
            valueDisplay = '<span class="rb-absent">not set</span>';
        } else if (tag.is_default) {
            valueDisplay = `<span class="rb-default">${escapeHtml(tag.value)} <span class="rb-default-label">(default)</span></span>`;
        } else {
            valueDisplay = `<span class="rb-value">${escapeHtml(tag.value || '')}</span>`;
        }

        // Per-tag warnings
        let warningsHtml = '';
        if (tag.warnings && tag.warnings.length > 0) {
            warningsHtml = tag.warnings.map(w => {
                const warnClass = w.level === 'warning' ? 'rb-tag-warn' : 'rb-tag-info';
                return `<div class="${warnClass}">${escapeHtml(w.text)}</div>`;
            }).join('');
        }

        // Fallback chain (for np= absent)
        let chainHtml = '';
        if (tag.fallback_chain && tag.fallback_chain.length > 0) {
            const links = tag.fallback_chain.map(link => {
                const val = link.value != null ? `=${escapeHtml(link.value)}` : '';
                const cls = link.active ? 'rb-chain-active' : 'rb-chain-inactive';
                return `<span class="rb-chain-link ${cls}">${escapeHtml(link.tag)}${val}</span>`;
            }).join('<span class="rb-chain-arrow">&#8594;</span>');
            chainHtml = `<div class="rb-fallback-chain">${links}</div>`;
        }

        // DMARCbis note callout
        let noteHtml = '';
        if (tag.dmarcbis_note) {
            noteHtml = `<div class="rb-bis-note"><span class="rb-bis-note-label">DMARCbis</span> ${escapeHtml(tag.dmarcbis_note)}</div>`;
        }

        tagsHtml += `
            <div class="rb-tag-row">
                <div class="rb-tag-header">
                    <code class="rb-tag-name">${escapeHtml(tag.tag)}=</code>
                    ${valueDisplay}
                    <span class="rb-bis-badge ${bisClass}">${escapeHtml(bisLabel)}</span>
                </div>
                <div class="rb-tag-label">${escapeHtml(tag.label)}</div>
                <div class="rb-tag-explain">${escapeHtml(tag.explanation || '')}</div>
                ${chainHtml}
                ${warningsHtml}
                ${noteHtml}
            </div>`;
    });

    // --- Configuration Warnings (Prompt 2) ---
    let configWarningsHtml = '';
    if (bd.config_warnings && bd.config_warnings.length > 0) {
        let items = '';
        bd.config_warnings.forEach(w => {
            const cls = w.level === 'critical' ? 'rb-cw-critical'
                : w.level === 'info' ? 'rb-cw-info' : 'rb-cw-advisory';
            const icon = w.level === 'critical' ? '&#10005;'
                : w.level === 'info' ? '&#8505;' : '&#9888;';
            const tagPills = w.tags.map(t => `<code class="rb-cw-tag">${escapeHtml(t)}</code>`).join(' ');
            items += `
                <div class="rb-cw-item ${cls}">
                    <div class="rb-cw-header">
                        <span class="rb-cw-icon">${icon}</span>
                        <span class="rb-cw-title">${escapeHtml(w.title)}</span>
                        ${tagPills}
                    </div>
                    <div class="rb-cw-text">${escapeHtml(w.text)}</div>
                </div>`;
        });
        configWarningsHtml = `
            <div class="rb-config-warnings">
                <div class="rb-cw-label">Configuration Analysis</div>
                ${items}
            </div>`;
    }

    // --- Migration Wizard (Prompt 3) ---
    let migrationHtml = '';
    if (bd.migration && bd.migration.steps && bd.migration.steps.length > 0) {
        let stepsHtml = '';
        bd.migration.steps.forEach(s => {
            const hasRecord = s.record_after ? `
                <div class="mw-record">
                    <span class="mw-record-text">${escapeHtml(s.record_after)}</span>
                </div>` : '';
            const tagBadges = (s.tags_changed || []).map(t =>
                `<code class="mw-tag-badge">${escapeHtml(t)}</code>`
            ).join(' ');

            stepsHtml += `
                <div class="mw-step">
                    <div class="mw-step-num">${s.step}</div>
                    <div class="mw-step-body">
                        <div class="mw-step-action">${escapeHtml(s.action)} ${tagBadges}</div>
                        <div class="mw-step-why">${escapeHtml(s.why)}</div>
                        ${hasRecord}
                    </div>
                </div>`;
        });

        migrationHtml = `
            <div class="mw-block">
                <div class="mw-header">
                    <span class="mw-title">Migration Path to DMARCbis Ready</span>
                    <span class="mw-progress">${bd.migration.total_steps} steps</span>
                </div>
                <div class="mw-steps">${stepsHtml}</div>
                <div class="mw-target">
                    <div class="mw-target-label">Target DMARCbis-Ready Record</div>
                    <div class="record-block" style="margin: 0.4rem 0;">
                        <span class="record-text">${escapeHtml(bd.migration.target_record)}</span>
                        <button class="copy-btn">Copy</button>
                    </div>
                </div>
            </div>`;
    } else if (bd.migration && bd.migration.status === 'ready') {
        migrationHtml = `
            <div class="mw-block mw-ready">
                <span class="mw-ready-check">&#10003;</span>
                <span class="mw-ready-text">No migration needed. This record is DMARCbis Ready.</span>
            </div>`;
    }

    // --- Why DMARCbis? Education Section (Prompt 4) ---
    let whyHtml = '';
    if (bd.why_dmarcbis && bd.why_dmarcbis.sections) {
        let sectionsHtml = '';
        bd.why_dmarcbis.sections.forEach(sec => {
            let body = '';
            if (sec.content) {
                body += `<p class="wd-content">${escapeHtml(sec.content)}</p>`;
            }
            if (sec.items && sec.items.length > 0) {
                body += sec.items.map(item =>
                    `<div class="wd-item">${escapeHtml(item)}</div>`
                ).join('');
            }
            if (sec.verdict_scale) {
                body += '<div class="wd-scale">';
                sec.verdict_scale.forEach(v => {
                    const active = v.status === sec.current_verdict ? ' wd-scale-active' : '';
                    body += `<span class="wd-scale-item wd-scale-${v.color}${active}">${escapeHtml(v.label)}</span>`;
                });
                body += '</div>';
            }
            sectionsHtml += `
                <div class="wd-section">
                    <div class="wd-section-title">${escapeHtml(sec.title)}</div>
                    ${body}
                </div>`;
        });

        whyHtml = `
            <div class="wd-block">
                <details>
                    <summary class="wd-summary">
                        <span class="wd-summary-icon">&#128218;</span>
                        <span class="wd-summary-text">Why DMARCbis?</span>
                    </summary>
                    <div class="wd-body">${sectionsHtml}</div>
                </details>
            </div>`;
    }

    return `
        <div class="record-breakdown">
            <div class="rb-header">
                <span class="rb-title">DMARC Record Breakdown</span>
            </div>
            ${verdictHtml}
            <div class="rb-tags">${tagsHtml}</div>
            ${configWarningsHtml}
            ${migrationHtml}
            ${whyHtml}
        </div>`;
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
                <a class="tw-spec-badge" href="https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/"
                   target="_blank" rel="noopener">DMARCbis</a>
            </div>
            <div class="tw-simple-body">
                <span class="tw-simple-check">&#10003;</span>
                <span><strong>${domain}</strong> publishes its own DMARC record. No policy inheritance needed.</span>
            </div>
            <div class="tw-simple-policy">
                Policy: <span class="tw-pill ${policyClass}">${policy}</span>
            </div>
            <div class="tw-footnote">
                Under <a href="https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/" target="_blank" rel="noopener">DMARCbis</a>,
                receivers walk up the DNS hierarchy to find an applicable DMARC policy when a domain lacks its own record.
                This domain has a direct record, so the walk is not needed.
            </div>
        </div>`;
}

function renderTreeWalkFull(tw) {
    const specUrl = 'https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/';
    const stepCount = tw.steps.length;
    // Each step lands 150ms after the previous; metadata appears after the last step
    const stepInterval = 0.15;            // seconds between steps
    const lastStepLands = 0.05 + (stepCount - 1) * stepInterval + 0.35; // delay + anim duration
    const metaDelay = (lastStepLands + 0.1).toFixed(2);

    let html = `
        <div class="tree-walk tw-animated">
            <div class="tw-header-row">
                <div class="tree-walk-header">DMARC Policy Discovery (Tree Walk)</div>
                <a class="tw-spec-badge" href="${specUrl}" target="_blank" rel="noopener">DMARCbis</a>
            </div>`;

    // Educational intro
    if (!tw.policy_source) {
        html += `<div class="tw-intro">This domain does not have its own DMARC record.
            Under <a href="${specUrl}" target="_blank" rel="noopener">DMARCbis</a>,
            receivers walk up the DNS hierarchy looking for an applicable policy.
            <strong>No policy was found.</strong></div>`;
    } else if (tw.is_subdomain) {
        html += `<div class="tw-intro">This domain does not have its own DMARC record.
            Under <a href="${specUrl}" target="_blank" rel="noopener">DMARCbis</a>,
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

        // Note for inherited policies
        if (tw.is_subdomain) {
            html += `<div class="tw-footnote" style="animation-delay:${metaDelay}s">
                This subdomain inherits its DMARC policy from the organizational domain.
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
// DMARCbis Readiness
// ============================================================

function renderDmarcbisReadiness(readiness) {
    if (!readiness || readiness.status === 'no_record') return '';

    const statusLabels = {
        'compliant': 'DMARCbis Ready',
        'compatible': 'DMARCbis Compatible',
        'non_compliant': 'Needs Update'
    };
    const statusColors = {
        'compliant': 'pass',
        'compatible': 'warn',
        'non_compliant': 'fail'
    };

    const statusLabel = statusLabels[readiness.status] || 'Unknown';
    const statusClass = statusColors[readiness.status] || 'warn';

    // Checklist items
    let checklistHtml = '';
    readiness.checklist.forEach(item => {
        const iconClass = item.status === 'pass' ? 'tw-hit'
            : item.status === 'warn' ? 'tw-psd'
                : 'dbis-info-icon';
        const icon = item.status === 'pass' ? '&#10003;'
            : item.status === 'warn' ? '&#9651;'
                : '&#8505;';
        const detail = item.detail
            ? `<span class="dbis-tag">${escapeHtml(item.detail)}</span>`
            : '';

        // Per-tag deprecation details (expanded under the checklist item)
        let subDetailsHtml = '';
        if (item.deprecated_details && item.deprecated_details.length > 0) {
            let depItems = '';
            item.deprecated_details.forEach(dep => {
                depItems += `
                    <div class="dbis-dep-item">
                        <span class="dbis-dep-tag">${escapeHtml(dep.tag)}</span>
                        <span class="dbis-dep-reason">${escapeHtml(dep.reason)}</span>
                    </div>`;
            });
            subDetailsHtml = `<div class="dbis-dep-details">${depItems}</div>`;
        }

        // NP precedence chain
        if (item.np_chain && item.np_chain.length > 0) {
            let chainItems = item.np_chain.map(link => {
                const val = link.value != null ? `=${escapeHtml(link.value)}` : '';
                const cls = link.active ? 'dbis-chain-active' : 'dbis-chain-inactive';
                return `<span class="dbis-chain-link ${cls}">${escapeHtml(link.tag)}${val}</span>`;
            }).join('<span class="dbis-chain-arrow">&#8594;</span>');
            let fallbackNote = item.np_fallback_note
                ? `<div class="dbis-chain-note">${escapeHtml(item.np_fallback_note)}</div>`
                : '';
            subDetailsHtml += `<div class="dbis-np-chain">
                <div class="dbis-chain-label">Non-existent subdomain policy precedence:</div>
                <div class="dbis-chain-links">${chainItems}</div>
                ${fallbackNote}
            </div>`;
        }

        checklistHtml += `
            <div class="dbis-check-item">
                <span class="${iconClass}">${icon}</span>
                <span class="dbis-check-label">${escapeHtml(item.label)}</span>
                ${detail}
            </div>
            ${subDetailsHtml}`;
    });

    // Suggested record with changes
    let suggestedHtml = '';
    if (readiness.suggested_record && readiness.changes && readiness.changes.length > 0) {
        let changesHtml = '';
        readiness.changes.forEach(change => {
            const changeClass = change.type === 'removed' ? 'dbis-removed' : 'dbis-added';
            const changeLabel = change.type === 'removed' ? 'REMOVED' : 'ADDED';
            changesHtml += `
                <div class="dbis-change">
                    <span class="${changeClass}">${changeLabel}</span>
                    <span class="dbis-change-tag">${escapeHtml(change.tag)}</span>
                    <span class="dbis-change-reason">${escapeHtml(change.reason)}</span>
                </div>`;
        });

        suggestedHtml = `
            <div class="dbis-suggested">
                <div class="dbis-suggested-label">Suggested DMARCbis Record</div>
                <div class="record-block" style="margin: 0.5rem 0;">
                    <span class="record-text">${escapeHtml(readiness.suggested_record)}</span>
                </div>
                <div class="dbis-changes">${changesHtml}</div>
            </div>`;
    }

    return `
        <div class="dbis-readiness-block">
            <div class="dbis-header">
                <div class="dbis-header-left">
                    <span class="dbis-badge">DMARCbis</span>
                    <span class="dbis-title">DMARCbis Readiness</span>
                </div>
                <div class="dbis-header-right">
                    <span class="dbis-status dbis-status-${statusClass}">${escapeHtml(statusLabel)}</span>
                    <span class="dbis-score">${readiness.pass_count}/${readiness.total_count}</span>
                </div>
            </div>
            <div class="dbis-checklist">${checklistHtml}</div>
            ${suggestedHtml}
        </div>`;
}

// ============================================================
// Security Roadmap
// ============================================================

function renderSecurityRoadmap(rm) {
    if (!rm || !rm.items || rm.items.length === 0) return '';

    const priorityLabels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
    const priorityColors = { critical: 'fail', high: 'warn', medium: 'info', low: 'pass' };

    // Progress bar
    const total = rm.total;
    const tierSummary = Object.entries(rm.tiers)
        .filter(([_, v]) => v > 0)
        .map(([k, v]) => `${v} ${priorityLabels[k].toLowerCase()}`)
        .join(', ');

    // Group items by priority
    let itemsHtml = '';
    ['critical', 'high', 'medium', 'low'].forEach(tier => {
        const tierItems = rm.items.filter(i => i.priority === tier);
        if (tierItems.length === 0) return;

        let rows = tierItems.map(item =>
            `<div class="sr-item sr-item-${priorityColors[item.priority]}">
                <span class="sr-protocol">${escapeHtml(item.protocol)}</span>
                <div class="sr-item-body">
                    <div class="sr-action">${escapeHtml(item.action)}</div>
                    <div class="sr-impact">${escapeHtml(item.impact)}</div>
                </div>
            </div>`
        ).join('');

        itemsHtml += `
            <div class="sr-tier">
                <div class="sr-tier-label sr-tier-${priorityColors[tier]}">${escapeHtml(priorityLabels[tier])}</div>
                ${rows}
            </div>`;
    });

    return `
        <div class="sr-block">
            <div class="sr-header">
                <span class="sr-title">Email Security Roadmap</span>
                <span class="sr-summary">${escapeHtml(tierSummary)}</span>
            </div>
            ${itemsHtml}
        </div>`;
}

// ============================================================
// DKIM Key Analysis
// ============================================================

function renderDkimKeyAnalysis(dk) {
    if (!dk || !dk.keys || dk.keys.length === 0) return '';

    let keysHtml = '';
    dk.keys.forEach(k => {
        const ratingClass = `dk-rating-${k.rating}`;
        const providerBadge = k.provider ? `<span class="spfd-provider">${escapeHtml(k.provider)}</span>` : '';

        let tagsHtml = '';
        if (k.tags && k.tags.length > 0) {
            tagsHtml = k.tags.map(t => {
                let val = t.truncated || t.value || '';
                if (t.revoked) val = '(empty - REVOKED)';
                const cls = t.revoked ? 'dk-tag-revoked' : '';
                return `<div class="dk-tag ${cls}"><code>${escapeHtml(t.tag)}=</code> <span class="dk-tag-label">${escapeHtml(t.label)}</span></div>`;
            }).join('');
            tagsHtml = `<div class="dk-tags">${tagsHtml}</div>`;
        }

        keysHtml += `
            <div class="dk-key ${ratingClass}">
                <div class="dk-key-header">
                    <code class="dk-selector">${escapeHtml(k.selector)}</code>
                    <span class="dk-key-info">${k.bits > 0 ? k.bits + '-bit ' : ''}${escapeHtml(k.key_type)}</span>
                    ${providerBadge}
                    <span class="as-vector-badge as-badge-${k.rating}">${escapeHtml(k.rating_label.split('.')[0])}</span>
                </div>
                <div class="dk-key-detail">${escapeHtml(k.rating_label)}</div>
                ${tagsHtml}
            </div>`;
    });

    return `
        <div class="dk-block">
            <div class="spfd-header">
                <span class="spfd-title">DKIM Key Analysis</span>
            </div>
            ${keysHtml}
            <div class="dk-rotation">${escapeHtml(dk.rotation_guidance)}</div>
        </div>`;
}

// ============================================================
// SPF Deep Analysis
// ============================================================

function renderSpfDeepAnalysis(spf) {
    if (!spf) return '';

    // DMARCbis context note
    let noteHtml = `<div class="rb-bis-note" style="margin-bottom:0.6rem;"><span class="rb-bis-note-label">DMARCbis</span> ${escapeHtml(spf.dmarcbis_note)}</div>`;

    // Mechanism table
    let mechHtml = '';
    if (spf.mechanisms && spf.mechanisms.length > 0) {
        let rows = '';
        spf.mechanisms.forEach(m => {
            const costDisplay = m.cost > 0 ? `<span class="spfd-cost">${m.cost}</span>` : '<span class="spfd-cost spfd-cost-zero">0</span>';
            const providerBadge = m.provider ? `<span class="spfd-provider">${escapeHtml(m.provider)}</span>` : '';
            rows += `
                <div class="spfd-mech-row">
                    <code class="spfd-mech-raw">${escapeHtml(m.raw)}</code>
                    ${costDisplay}
                    ${providerBadge}
                </div>`;
        });
        mechHtml = `
            <div class="spfd-mechs">
                <div class="spfd-mechs-header">
                    <span>Mechanism</span><span>Lookups</span><span>Service</span>
                </div>
                ${rows}
            </div>`;
    }

    // All-mechanism
    let allHtml = '';
    if (spf.all_mechanism || spf.all_explanation) {
        const allClass = spf.all_severity === 'critical' ? 'spfd-all-critical'
            : spf.all_severity === 'warning' ? 'spfd-all-warning' : 'spfd-all-info';
        allHtml = `
            <div class="spfd-all ${allClass}">
                <code class="spfd-all-mech">${escapeHtml(spf.all_mechanism || '(none)')}</code>
                <span class="spfd-all-text">${escapeHtml(spf.all_explanation)}</span>
            </div>`;
    }

    // Misconfigurations
    let misconfigHtml = '';
    if (spf.misconfigs && spf.misconfigs.length > 0) {
        let items = spf.misconfigs.map(m => {
            const cls = m.level === 'critical' ? 'rb-cw-critical' : m.level === 'warning' ? 'rb-cw-advisory' : 'rb-cw-info';
            const icon = m.level === 'critical' ? '&#10005;' : '&#9888;';
            return `<div class="rb-cw-item ${cls}">
                <div class="rb-cw-header"><span class="rb-cw-icon">${icon}</span><span class="rb-cw-title">${escapeHtml(m.title)}</span></div>
                <div class="rb-cw-text">${escapeHtml(m.text)}</div>
            </div>`;
        }).join('');
        misconfigHtml = `<div class="spfd-misconfigs">${items}</div>`;
    }

    // Optimizations
    let optHtml = '';
    if (spf.optimizations && spf.optimizations.length > 0) {
        optHtml = spf.optimizations.map(o =>
            `<div class="spfd-opt">${escapeHtml(o)}</div>`
        ).join('');
    }

    return `
        <div class="spfd-block">
            <div class="spfd-header">
                <span class="spfd-title">SPF Record Analysis</span>
                <span class="spfd-lookup-badge">${spf.lookup_count}/10 lookups</span>
            </div>
            ${noteHtml}
            ${mechHtml}
            ${allHtml}
            ${misconfigHtml}
            ${optHtml}
        </div>`;
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
            const safeRange = escapeHtml(step.lookup_range);
            const label = step.lookup_range.includes('-')
                ? `lookups ${safeRange}`
                : `lookup ${safeRange}`;
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

    const spfPillClass = (ev.spf_result === 'pass' || ev.spf_result === 'configured') ? 'de-pill-pass'
        : ev.spf_result === 'none' ? 'de-pill-muted'
            : 'de-pill-fail';
    const dkimPillClass = (ev.dkim_result === 'pass' || ev.dkim_result === 'configured') ? 'de-pill-pass'
        : ev.dkim_result === 'none' ? 'de-pill-muted'
            : 'de-pill-fail';
    const dmarcPillClass = (ev.dmarc_result === 'pass' || ev.dmarc_result === 'configured') ? 'de-pill-pass' : 'de-pill-fail';
    const policyPillClass = ev.policy === 'reject' ? 'de-pill-pass'
        : ev.policy === 'quarantine' ? 'de-pill-warn'
            : 'de-pill-muted';

    const spfAlignIcon = ev.spf_aligned ? '&#10003; alignment possible' : '&#10005; not configured';
    const spfAlignClass = ev.spf_aligned ? 'de-aligned' : 'de-not-aligned';
    const dkimAlignIcon = ev.dkim_aligned ? '&#10003; alignment possible' : '&#10005; not configured';
    const dkimAlignClass = ev.dkim_aligned ? 'de-aligned' : 'de-not-aligned';

    const dispLabel = ev.disposition === 'none' ? 'delivered'
        : ev.disposition === 'quarantine' ? 'quarantined'
            : ev.disposition === 'reject' ? 'rejected'
                : escapeHtml(ev.disposition);

    const mailingListNote = ev.policy === 'reject'
        ? `<div class="de-mailing-list-note">DMARCbis notes that p=reject can cause delivery failures for messages sent through mailing lists or forwarding services. Consider this if your domain participates in mailing lists.</div>`
        : '';

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
                    <span class="de-pill ${spfPillClass}">${escapeHtml(ev.spf_result)}</span>
                    <span class="de-align-mode">${escapeHtml(ev.spf_alignment_mode)}</span>
                    <span class="de-align-result ${spfAlignClass}">${spfAlignIcon}</span>
                    <span class="de-note">DMARCbis evaluates SPF alignment against MAIL FROM only (not HELO)</span>
                </div>
                <div class="de-row">
                    <span class="de-protocol">DKIM</span>
                    <span class="de-pill ${dkimPillClass}">${escapeHtml(ev.dkim_result)}</span>
                    <span class="de-align-mode">${escapeHtml(ev.dkim_alignment_mode)}</span>
                    <span class="de-align-result ${dkimAlignClass}">${dkimAlignIcon}</span>
                </div>
                <div class="de-row de-final">
                    <span class="de-protocol">DMARC</span>
                    <span class="de-pill ${dmarcPillClass}">${escapeHtml(ev.dmarc_result)}</span>
                    <span class="de-policy-group">
                        policy: <span class="de-pill ${policyPillClass}">${escapeHtml(ev.policy)}</span>
                    </span>
                    <span class="de-disposition">${escapeHtml(dispLabel)}</span>
                </div>
            </div>
            ${mailingListNote}
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
        html += `<div class="rc-footnote">Note: Most mailbox providers no longer send failure reports (ruf) because they can contain PII (message headers, recipient addresses).</div>`;
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
    if (!lastAuditData || !lastAuditData.domain) return;
    const domain = encodeURIComponent(lastAuditData.domain);
    const scope = currentScope || 'complete';
    const selectorVal = document.getElementById('selector-input')?.value?.trim() || '';
    const selectorParam = selectorVal ? `&selector=${encodeURIComponent(selectorVal)}` : '';
    window.open(`/api/audit/${domain}/pdf?scope=${scope}${selectorParam}`, '_blank');
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
// Score count-up animation
// ============================================================

function _animateScore(element, target) {
    const duration = 600;
    const start = performance.now();
    function update(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        element.textContent = Math.round(eased * target) + ' / 100';
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

// ============================================================
// Copy All Records
// ============================================================

document.getElementById('copy-all-btn').addEventListener('click', () => {
    const records = [];
    document.querySelectorAll('.record-text').forEach(el => {
        const text = el.textContent.trim();
        if (text) records.push(text);
    });
    if (records.length === 0) {
        records.push('No DNS records found.');
    }
    const output = records.join('\n\n');
    const btn = document.getElementById('copy-all-btn');
    const span = btn.querySelector('span');
    _copyToClipboard(output, span, 'Copy All Records');
    btn.classList.add('copied');
    setTimeout(() => btn.classList.remove('copied'), 2000);
});

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

