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

    // Grade color-coding and score display
    const gradeCard = document.querySelector('.grade-card');
    const gradeEl = document.getElementById('summary-grade');
    const grade = data.score?.grade || '--';
    const gradeColors = {
      'A': { bg: '#ecfdf5', border: '#10b981', text: '#065f46' },
      'B': { bg: '#eff6ff', border: '#3b82f6', text: '#1e40af' },
      'C': { bg: '#fffbeb', border: '#f59e0b', text: '#92400e' },
      'D': { bg: '#fff7ed', border: '#f97316', text: '#9a3412' },
      'F': { bg: '#fef2f2', border: '#ef4444', text: '#991b1b' }
    };
    const gc = gradeColors[grade];
    if (gc && gradeCard) {
      gradeCard.style.borderTopColor = gc.border;
      gradeCard.style.background = gc.bg;
      gradeEl.style.color = gc.text;
    }
    // Show score number below grade
    const scoreNum = data.score?.total;
    if (scoreNum !== undefined && gradeCard) {
      let scoreEl = document.getElementById('summary-score');
      if (!scoreEl) {
        scoreEl = document.createElement('div');
        scoreEl.id = 'summary-score';
        scoreEl.style.cssText = 'font-size:0.82rem;color:var(--text-secondary);font-weight:500;margin-top:0.15rem;';
        gradeEl.parentNode.insertBefore(scoreEl, gradeEl.nextSibling);
      }
      scoreEl.textContent = Math.round(scoreNum) + ' / 100';
    }

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

    // Tree Walk Visualization
    if (data.tree_walk) {
      renderTreeWalk(data.tree_walk);
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


// ============================================================
// DMARC DNS Tree Walk Visualization
// Per draft-ietf-dmarc-dmarcbis-41, Section 4.10
// ============================================================

function renderTreeWalk(tw) {
  // Remove any previous tree walk section
  const existing = document.getElementById('tree-walk-section');
  if (existing) existing.remove();

  if (!tw || !tw.steps || tw.steps.length === 0) return;

  const section = document.createElement('div');
  section.id = 'tree-walk-section';
  section.className = 'tree-walk-section';

  const policyFound = !!tw.policy_source;
  const policyTag = tw.applied_tag || 'p';

  // Header
  section.innerHTML = `
    <div class="tw-header">
      <div class="tw-header-left">
        <svg class="tw-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="22" height="22">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
        </svg>
        <div>
          <div class="tw-title">DMARC Policy Discovery</div>
          <div class="tw-subtitle">DNS Tree Walk per <a href="https://datatracker.ietf.org/doc/draft-ietf-dmarc-dmarcbis/" target="_blank" rel="noopener">dmarcbis</a> Section 4.10</div>
        </div>
      </div>
      <div class="tw-badge ${policyFound ? 'tw-badge-found' : 'tw-badge-none'}">
        ${policyFound ? 'Policy Found' : 'No Policy'}
      </div>
    </div>
    <div class="tw-explainer">
      When a mail receiver gets an email from <strong>${escapeHtml(tw.domain)}</strong>, it needs to find the DMARC policy that applies.
      It starts by querying the exact domain, then walks up the DNS hierarchy until it finds a published policy.
    </div>
    <div class="tw-tree" id="tw-tree"></div>
    ${policyFound ? `
    <div class="tw-result tw-result-found">
      <div class="tw-result-header">
        <div class="tw-result-dot"></div>
        <span>Effective policy from <strong>${escapeHtml(tw.policy_source)}</strong></span>
        <span class="tw-policy-pill tw-policy-${tw.effective_policy}">${tw.effective_policy}</span>
      </div>
      <div class="tw-result-details">
        <div class="tw-result-row"><span class="tw-result-label">Applied tag:</span> <code>${policyTag}</code>${tw.is_subdomain ? ' (subdomain inherits from parent)' : ' (direct match)'}</div>
        <div class="tw-result-row"><span class="tw-result-label">Record:</span> <code class="tw-record-code">${escapeHtml(tw.effective_record)}</code></div>
        ${tw.psd_flag ? `<div class="tw-result-row"><span class="tw-result-label">PSD flag:</span> <code>${tw.psd_flag}</code></div>` : ''}
      </div>
    </div>
    ` : `
    <div class="tw-result tw-result-none">
      <div class="tw-result-header">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
          <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
        <span>No DMARC policy found at any level</span>
      </div>
      <div class="tw-result-details">
        Anyone can send email pretending to be from this domain. Mail receivers have no guidance on how to handle unauthenticated messages.
      </div>
    </div>
    `}
  `;

  // Insert before the "Detailed Results" label
  const resultsLabel = document.querySelector('.results-label');
  if (resultsLabel) {
    resultsLabel.parentNode.insertBefore(section, resultsLabel);
  } else {
    document.getElementById('results-section').appendChild(section);
  }

  // Now animate the tree nodes
  const treeContainer = document.getElementById('tw-tree');
  animateTreeWalk(tw.steps, treeContainer, tw.policy_source);
}

function animateTreeWalk(steps, container, policySource) {
  // Build all nodes first (hidden)
  steps.forEach((step, i) => {
    const node = document.createElement('div');
    node.className = 'tw-node tw-node-hidden';
    node.dataset.index = i;

    const isMatch = step.found && step.domain === policySource;
    const isLast = i === steps.length - 1;

    node.innerHTML = `
      <div class="tw-connector ${i === 0 ? 'tw-connector-first' : ''}">
        <div class="tw-connector-line"></div>
        <div class="tw-connector-dot ${step.found ? 'tw-dot-found' : 'tw-dot-empty'}">
          ${step.found
            ? '<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" width="14" height="14"><polyline points="20 6 9 17 4 12"></polyline></svg>'
            : '<svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="3" width="14" height="14"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>'
          }
        </div>
      </div>
      <div class="tw-node-body ${isMatch ? 'tw-node-match' : ''} ${step.found && !isMatch ? 'tw-node-found' : ''} ${!step.found ? 'tw-node-miss' : ''}">
        <div class="tw-node-level">${escapeHtml(step.label)}</div>
        <div class="tw-node-query">
          <code>_dmarc.${escapeHtml(step.domain)}</code>
          <span class="tw-node-status ${step.found ? 'tw-status-found' : 'tw-status-miss'}">
            ${step.found ? 'Record found' : 'No record'}
          </span>
        </div>
        ${step.found && step.record ? `
          <div class="tw-node-record"><code>${escapeHtml(step.record.length > 80 ? step.record.substring(0, 80) + '...' : step.record)}</code></div>
        ` : ''}
      </div>
    `;

    container.appendChild(node);
  });

  // Animate nodes appearing one by one
  const nodes = container.querySelectorAll('.tw-node');
  nodes.forEach((node, i) => {
    setTimeout(() => {
      node.classList.remove('tw-node-hidden');
      node.classList.add('tw-node-entering');

      // After enter animation, add the "probing" pulse
      setTimeout(() => {
        node.classList.remove('tw-node-entering');
        node.classList.add('tw-node-visible');

        const dot = node.querySelector('.tw-connector-dot');
        if (dot) {
          dot.classList.add('tw-dot-pulse');
          setTimeout(() => dot.classList.remove('tw-dot-pulse'), 600);
        }
      }, 400);
    }, i * 500);
  });
}
