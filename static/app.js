/* ==========================================================================
   DNS Security Auditor - Frontend Application
   ========================================================================== */

const API_BASE = '/api';

// -- DOM References --
const auditForm = document.getElementById('audit-form');
const domainInput = document.getElementById('domain-input');
const auditBtn = document.getElementById('audit-btn');
const loadingSection = document.getElementById('loading-section');
const loadingBar = document.getElementById('loading-bar');
const loadingStatus = document.getElementById('loading-status');
const resultsSection = document.getElementById('results-section');

// -- Check URL for domain parameter on load --
document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const domain = params.get('d');
    if (domain) {
        domainInput.value = domain;
        runAudit(domain);
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
    showLoading();
    hideResults();

    try {
        const resp = await fetch(`${API_BASE}/audit?domain=${encodeURIComponent(domain)}`);

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

// -- Error display --
function showError(message) {
    // Reuse loading section for error display
    loadingSection.style.display = 'block';
    const card = loadingSection.querySelector('.loading-card');
    card.innerHTML = `
        <div style="color: var(--fail); font-weight: 600; margin-bottom: 0.35rem;">Audit Failed</div>
        <div style="color: var(--text-secondary); font-size: 0.88rem;">${escapeHtml(message)}</div>
        <button onclick="location.reload()" style="
            margin-top: 0.75rem; padding: 0.5rem 1rem; background: var(--primary);
            color: white; border: none; border-radius: var(--radius); cursor: pointer;
            font-family: var(--font-body); font-size: 0.85rem; font-weight: 600;
        ">Try Again</button>
    `;
}

// -- Loading states --
const LOADING_STEPS = [
    { pct: 10, msg: 'Resolving DNS records...' },
    { pct: 20, msg: 'Checking DMARC policy...' },
    { pct: 30, msg: 'Analyzing SPF configuration...' },
    { pct: 45, msg: 'Discovering DKIM selectors...' },
    { pct: 55, msg: 'Checking MX records...' },
    { pct: 65, msg: 'Validating MTA-STS...' },
    { pct: 72, msg: 'Checking TLS-RPT...' },
    { pct: 78, msg: 'Looking for BIMI record...' },
    { pct: 85, msg: 'Fingerprinting email services...' },
    { pct: 92, msg: 'Calculating security score...' },
];

function showLoading() {
    loadingSection.style.display = 'block';
    // Reset loading card content (in case error was displayed before)
    const card = loadingSection.querySelector('.loading-card');
    card.innerHTML = `
        <div class="loading-bar-track">
            <div class="loading-bar-fill" id="loading-bar"></div>
        </div>
        <div class="loading-status" id="loading-status">Resolving DNS records...</div>
    `;
    resultsSection.style.display = 'none';
    auditBtn.disabled = true;
    auditBtn.querySelector('.btn-text').style.display = 'none';
    auditBtn.querySelector('.btn-loading').style.display = 'flex';

    const bar = document.getElementById('loading-bar');
    const status = document.getElementById('loading-status');
    if (bar) bar.style.width = '0%';

    let step = 0;
    window._loadingInterval = setInterval(() => {
        if (step < LOADING_STEPS.length) {
            if (bar) bar.style.width = LOADING_STEPS[step].pct + '%';
            if (status) status.textContent = LOADING_STEPS[step].msg;
            step++;
        }
    }, 400);
}

function hideLoading() {
    loadingSection.style.display = 'none';
    auditBtn.disabled = false;
    auditBtn.querySelector('.btn-text').style.display = 'inline';
    auditBtn.querySelector('.btn-loading').style.display = 'none';
    if (window._loadingInterval) clearInterval(window._loadingInterval);
}

function hideResults() {
    resultsSection.style.display = 'none';
}

// -- Render results --
function renderResults(data) {
    // Finish loading animation
    const bar = document.getElementById('loading-bar');
    const status = document.getElementById('loading-status');
    if (bar) bar.style.width = '100%';
    if (status) status.textContent = 'Complete';

    setTimeout(() => {
        hideLoading();
        resultsSection.style.display = 'block';

        // Update URL for sharing
        const url = new URL(window.location);
        url.searchParams.set('d', data.domain);
        window.history.replaceState({}, '', url);
    }, 300);

    // Domain banner
    document.getElementById('result-domain').textContent = data.domain;
    document.getElementById('result-timestamp').textContent = formatTimestamp(data.timestamp || new Date().toISOString());

    // Summary
    document.getElementById('summary-grade').textContent = data.score?.grade || '--';
    document.getElementById('summary-pass').textContent = countByStatus(data.checks, 'pass');
    document.getElementById('summary-warn').textContent = countByStatus(data.checks, 'warn');
    document.getElementById('summary-fail').textContent = countByStatus(data.checks, 'fail');

    // Priority fixes
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

    // Result cards
    const resultsList = document.getElementById('results-list');
    resultsList.innerHTML = '';

    if (data.checks) {
        data.checks.forEach(check => {
            resultsList.appendChild(createResultCard(check));
        });
    }

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
                <div class="vendor-confidence">${v.confidence}%</div>
            `;
            vendorsGrid.appendChild(card);
        });
    } else {
        vendorsSection.style.display = 'none';
    }

    // Share button
    document.getElementById('share-btn').onclick = () => {
        navigator.clipboard.writeText(window.location.href).then(() => {
            const btn = document.getElementById('share-btn');
            btn.querySelector('span').textContent = 'Copied!';
            setTimeout(() => btn.querySelector('span').textContent = 'Share', 2000);
        });
    };
}

// -- Create a single result card --
function createResultCard(check) {
    const card = document.createElement('div');
    card.className = `result-card ${check.status === 'fail' || check.status === 'warn' ? 'expanded' : ''}`;

    const statusLabel = check.pill_label || {
        pass: 'Pass',
        warn: 'Warning',
        fail: 'Issue'
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
            const record = btn.closest('.record-block').querySelector('.record-text')?.textContent
                || btn.closest('.record-block').textContent.replace('Copy', '').trim();
            navigator.clipboard.writeText(record).then(() => {
                btn.textContent = 'Copied';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.textContent = 'Copy';
                    btn.classList.remove('copied');
                }, 2000);
            });
        });
    });

    return card;
}

function renderCheckBody(check) {
    let html = '';

    // Record
    if (check.record) {
        html += `
            <div class="record-block">
                <span class="record-text">${escapeHtml(check.record)}</span>
                <button class="copy-btn">Copy</button>
            </div>
        `;
    }

    // Explanation (HTML allowed here -- it comes from our own transformer, not user input)
    if (check.explanation) {
        html += `<div class="explanation">${check.explanation}</div>`;
    }

    // Detail items
    if (check.details && check.details.length > 0) {
        check.details.forEach(d => {
            const typeClass = {
                error: 'fail-item',
                warning: 'warn-item',
                info: 'info-item',
                good: 'pass-item'
            }[d.type] || 'info-item';

            const icon = {
                error: '&#10005;',
                warning: '&#9888;',
                info: '&#8250;',
                good: '&#10003;'
            }[d.type] || '&#8250;';

            html += `
                <div class="detail-item ${typeClass}">
                    <span class="detail-icon">${icon}</span>
                    <span>${escapeHtml(d.text || '')}</span>
                </div>
            `;
        });
    }

    // Fix recommendation
    if (check.fix) {
        html += `
            <div class="fix-block">
                <div class="fix-label">Recommended Action</div>
                <div class="fix-text">${check.fix}</div>
            </div>
        `;
    }

    if (!html) {
        html = '<div class="explanation">No issues detected.</div>';
    }

    return html;
}

// -- Helpers --
function countByStatus(checks, status) {
    if (!checks) return 0;
    return checks.filter(c => c.status === status).length;
}

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
