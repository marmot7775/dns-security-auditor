/* ==========================================================================
   DNS Security Auditor - Frontend Application
   v2.0 — Scoped audits, severity sorting, auto-collapse
   ========================================================================== */

const API_BASE = '/api';

// -- Scope definitions: which checks to show per scope --
const SCOPE_CHECKS = {
    complete:      null, // null = show all
    email_full:    ['DMARC', 'SPF', 'DKIM', 'MX Records', 'MX', 'MTA-STS', 'TLS-RPT', 'BIMI', 'Blacklist'],
    dmarc:         ['DMARC'],
    transport:     ['MTA-STS', 'TLS-RPT', 'DANE', 'MX Records', 'MX'],
    dns_infra:     ['DNSSEC', 'CAA', 'DANE', 'Nameservers', 'Certificate Transparency'],
    security_scan: ['DMARC', 'SPF', 'DKIM', 'DNSSEC', 'DANE', 'Certificate Transparency', 'Blacklist'],
};

// Severity sort order (lower = higher priority = displayed first)
const SEVERITY_ORDER = { fail: 0, warn: 1, pass: 2 };

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
    showLoading();
    hideResults();

    try {
        const selectorVal = document.getElementById('selector-input')?.value?.trim() || '';
        let auditUrl = `${API_BASE}/audit?domain=${encodeURIComponent(domain)}`;
        if (selectorVal) auditUrl += `&selector=${encodeURIComponent(selectorVal)}`;
        const resp = await fetch(auditUrl);

        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `Audit failed (HTTP ${resp.status})`);
        }

        const data = await resp.json();
        renderResults(data);
    } catch (err) {
        console.error('Audit error:', err);
        hideLoading();
        showError(err.message || 'Audit failed. Please check the domain and try again.');
    }
}

// ============================================================
// Loading / Error
// ============================================================

const LOADING_STEPS = [
    { pct: 6,  msg: 'Resolving DNS records...' },
    { pct: 13, msg: 'Checking DMARC policy...' },
    { pct: 20, msg: 'Analyzing SPF configuration...' },
    { pct: 28, msg: 'Discovering DKIM selectors...' },
    { pct: 35, msg: 'Checking MX records...' },
    { pct: 42, msg: 'Validating MTA-STS...' },
    { pct: 48, msg: 'Checking TLS-RPT...' },
    { pct: 54, msg: 'Looking for BIMI record...' },
    { pct: 60, msg: 'Verifying DNSSEC chain...' },
    { pct: 66, msg: 'Checking CAA records...' },
    { pct: 72, msg: 'Checking DANE TLSA records...' },
    { pct: 78, msg: 'Querying certificate transparency logs...' },
    { pct: 85, msg: 'Checking IP and domain blocklists...' },
    { pct: 91, msg: 'Fingerprinting email services...' },
    { pct: 97, msg: 'Calculating security score...' },
];

function showLoading() {
    loadingSection.style.display = 'block';
    const card = loadingSection.querySelector('.loading-card');
    card.innerHTML = `
        <div class="loading-bar-track">
            <div class="loading-bar-fill" id="loading-bar"></div>
        </div>
        <div class="loading-status" id="loading-status">Resolving DNS records...</div>
    `;
    resultsSection.style.display = 'none';
    auditBtn.disabled = true;
    auditBtn.classList.add('is-loading');

    const bar    = document.getElementById('loading-bar');
    const status = document.getElementById('loading-status');
    if (bar) bar.style.width = '0%';

    let step = 0;
    window._loadingInterval = setInterval(() => {
        if (step < LOADING_STEPS.length) {
            if (bar) bar.style.width = LOADING_STEPS[step].pct + '%';
            if (status) status.textContent = LOADING_STEPS[step].msg;
            step++;
        }
    }, 350);
}

function hideLoading() {
    loadingSection.style.display = 'none';
    auditBtn.disabled = false;
    auditBtn.classList.remove('is-loading');
    if (window._loadingInterval) clearInterval(window._loadingInterval);
}

function hideResults() {
    resultsSection.style.display = 'none';
}

function showError(message) {
    loadingSection.style.display = 'block';
    const card = loadingSection.querySelector('.loading-card');
    card.innerHTML = `
        <div class="error-title">Audit Failed</div>
        <div class="error-message">${escapeHtml(message)}</div>
        <button class="error-retry" id="retry-btn">Try Again</button>
    `;
    document.getElementById('retry-btn').addEventListener('click', () => location.reload());
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

    setTimeout(() => {
        hideLoading();
        resultsSection.style.display = 'block';

        // Scroll results into view so user sees the report
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Update URL for sharing
        const url = new URL(window.location);
        url.searchParams.set('d', data.domain);
        url.searchParams.set('scope', currentScope);
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

    // -- Sort by severity: fail → warn → pass --
    checks.sort((a, b) => {
        const sa = SEVERITY_ORDER[a.status] ?? 3;
        const sb = SEVERITY_ORDER[b.status] ?? 3;
        return sa - sb;
    });

    // Summary counts (scoped)
    const passCount = checks.filter(c => c.status === 'pass').length;
    const warnCount = checks.filter(c => c.status === 'warn').length;
    const failCount = checks.filter(c => c.status === 'fail').length;

    document.getElementById('summary-grade').textContent = data.score?.grade || '--';
    document.getElementById('summary-pass').textContent = passCount;
    document.getElementById('summary-warn').textContent = warnCount;
    document.getElementById('summary-fail').textContent = failCount;

    // Grade color-coding
    const gradeCard = document.querySelector('.grade-card');
    const gradeEl   = document.getElementById('summary-grade');
    const grade = data.score?.grade || '--';
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
    // Score number
    const scoreNum = data.score?.total;
    if (scoreNum !== undefined && gradeCard) {
        let scoreEl = document.getElementById('summary-score');
        if (!scoreEl) {
            scoreEl = document.createElement('div');
            scoreEl.id = 'summary-score';
            scoreEl.className = 'score-subtext';
            gradeEl.parentNode.insertBefore(scoreEl, gradeEl.nextSibling);
        }
        scoreEl.textContent = Math.round(scoreNum) + ' / 100';
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

    checks.forEach((check, i) => {
        // Attach tree walk data to the DMARC check
        if ((check.name || '').toUpperCase().includes('DMARC') && data.tree_walk) {
            check._tree_walk = data.tree_walk;
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
        if (!navigator.clipboard) return;
        navigator.clipboard.writeText(window.location.href).then(() => {
            const span = document.getElementById('share-btn')?.querySelector('span');
            if (!span) return;
            span.textContent = 'Copied!';
            setTimeout(() => span.textContent = 'Share', 2000);
        }).catch(() => {});
    };
}

// ============================================================
// Result card — auto-collapse passing, expand fail/warn
// ============================================================

function createResultCard(check, index) {
    const card = document.createElement('div');
    // Auto-collapse: pass = collapsed, fail/warn = expanded
    const isExpanded = check.status !== 'pass';
    card.className = `result-card${isExpanded ? ' expanded' : ''}`;
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
    });

    // Copy buttons
    card.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (!navigator.clipboard) return;
            const block = btn.closest('.record-block');
            const record = block?.querySelector('.record-text')?.textContent
                || block?.textContent?.replace('Copy', '').trim() || '';
            navigator.clipboard.writeText(record).then(() => {
                btn.textContent = 'Copied';
                btn.classList.add('copied');
                setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
            }).catch(() => {});
        });
    });

    return card;
}

function renderCheckBody(check) {
    let html = '';

    // Record (dark-themed monospace block)
    if (check.record) {
        html += `
            <div class="record-block">
                <span class="record-text">${escapeHtml(check.record)}</span>
                <button class="copy-btn">Copy</button>
            </div>
        `;
    }

    // Explanation
    if (check.explanation) {
        html += `<div class="explanation">${sanitizeHtml(check.explanation)}</div>`;
    }

    // Detail items — sorted by severity within each card
    if (check.details && check.details.length > 0) {
        const detailOrder = { error: 0, warning: 1, info: 2, good: 3 };
        const sorted = [...check.details].sort((a, b) =>
            (detailOrder[a.type] ?? 4) - (detailOrder[b.type] ?? 4)
        );

        sorted.forEach(d => {
            const typeClass = {
                error: 'fail-item', warning: 'warn-item',
                info: 'info-item', good: 'pass-item'
            }[d.type] || 'info-item';
            const icon = {
                error: '&#10005;', warning: '&#9888;',
                info: '&#8250;', good: '&#10003;'
            }[d.type] || '&#8250;';

            html += `
                <div class="detail-item ${typeClass}">
                    <span class="detail-icon">${icon}</span>
                    <span>${escapeHtml(d.text || '')}</span>
                </div>
            `;
        });
    }

    // Tree walk visualization (DMARC only)
    if (check._tree_walk) {
        html += renderTreeWalk(check._tree_walk);
    }

    // Fix recommendation
    if (check.fix) {
        html += `
            <div class="fix-block">
                <div class="fix-label">Recommended Action</div>
                <div class="fix-text">${sanitizeHtml(check.fix)}</div>
            </div>
        `;
    }

    if (!html) {
        html = '<div class="explanation">No issues detected.</div>';
    }

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
                <div class="tree-walk-header">DMARC Policy Discovery</div>
                <a class="tw-spec-badge" href="https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/"
                   target="_blank" rel="noopener">dmarcbis</a>
            </div>
            <div class="tw-simple-body">
                <span class="tw-simple-check">&#10003;</span>
                <span><strong>${domain}</strong> publishes its own DMARC record &mdash; no policy inheritance needed.</span>
            </div>
            <div class="tw-simple-policy">
                Policy: <span class="tw-pill ${policyClass}">${policy}</span>
            </div>
            <div class="tw-footnote">
                Under <a href="https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/" target="_blank" rel="noopener">dmarcbis</a>,
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
                <div class="tree-walk-header">DMARC Policy Discovery</div>
                <a class="tw-spec-badge" href="${specUrl}" target="_blank" rel="noopener">dmarcbis</a>
            </div>`;

    // Educational intro
    if (!tw.policy_source) {
        html += `<div class="tw-intro">This domain does not have its own DMARC record.
            Under <a href="${specUrl}" target="_blank" rel="noopener">dmarcbis</a>,
            receivers walk up the DNS hierarchy looking for an applicable policy.
            <strong>No policy was found.</strong></div>`;
    } else if (tw.is_subdomain) {
        html += `<div class="tw-intro">This domain does not have its own DMARC record.
            Under <a href="${specUrl}" target="_blank" rel="noopener">dmarcbis</a>,
            receivers walk up the DNS hierarchy to find an applicable policy.</div>`;
    }

    // Timeline steps — pre-scan to find policy source index for line coloring
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
            <span class="tw-meta-value"><code>${escapeHtml(tag)}</code> &mdash; ${tagExplanation}</span>
        </div>`;

        const walkQueries = tw.query_count != null ? tw.query_count : (tw.steps.length - 1);
        html += `<div class="tw-meta-row">
            <span class="tw-meta-label">Walk Queries</span>
            <span class="tw-meta-value">${walkQueries} of 8 max</span>
        </div>`;

        html += `</div>`;
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
// Expand All / Collapse All
// ============================================================

(() => {
    const toggleBtn = document.getElementById('toggle-all-btn');
    let allExpanded = false;

    toggleBtn.addEventListener('click', () => {
        allExpanded = !allExpanded;
        document.querySelectorAll('.result-card').forEach(card => {
            card.classList.toggle('expanded', allExpanded);
        });
        toggleBtn.querySelector('span').textContent = allExpanded ? 'Collapse All' : 'Expand All';
    });
})();

// ============================================================
// Helpers
// ============================================================

function formatTimestamp(iso) {
    const d = new Date(iso);
    return d.toLocaleDateString('en-US', {
        year: 'numeric', month: 'short', day: 'numeric'
    }) + ' at ' + d.toLocaleTimeString('en-US', {
        hour: 'numeric', minute: '2-digit'
    });
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
    const ALLOWED_TAGS = ['strong', 'em', 'code', 'br', 'b', 'i'];
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
                    // Strip all attributes from allowed tags
                    while (child.attributes.length > 0) {
                        child.removeAttribute(child.attributes[0].name);
                    }
                    clean(child);
                }
            }
        }
    }

    clean(tmp);
    return tmp.innerHTML;
}

