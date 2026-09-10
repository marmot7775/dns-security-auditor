# Doc 32: About page rewrite, pluralization, and tone in app output

Two parts. Part A replaces the body copy of static/about.html. Part B fixes generated text that pluralizes wrong or dramatizes. Line numbers are from main at 076c1f5; re-locate by content if they have moved.

## Part A: About page

Replace everything inside `<main class="about-page">` in static/about.html with the markup below. Keep the head, header, and footer exactly as they are. Keep the existing classes (`dbis-section`, `about-closing`) so no CSS changes are needed. The email link is a plain mailto; do not obfuscate it.

    <h1>About</h1>
    <p>The tools I wanted didn't exist.</p>
    <p>Most DNS tools show you what records you have. They leave you to figure out whether those records are correct, whether the tag combination is dangerous, whether the RFC you're reading is the one that's actually current. I wanted something that did the analysis, showed the work, cited the specific RFC section it was checking against, and gave me the exact record to paste.</p>
    <p>So I built it.</p>
    <p>It checks your DNS and email security configuration against current standards, flags misconfigurations, and gives you copy-paste fixes. DMARC validation runs against the current standard, published May 2026 in three parts: RFC 9989 for the protocol, RFC 9990 for aggregate reporting, RFC 9991 for failure reporting. It also runs against RFC 7489 behavior, which most receivers still implement while tree walk support rolls out. You see both, and what changes between them. SPF, DKIM, MX, DNSSEC, MTA-STS, TLS-RPT, DANE, CAA, BIMI, Certificate Transparency, and nameserver configuration are all covered.</p>
    <p>If you manage DNS for a domain someone depends on, this tool was built for you.</p>
    <p>It's free. No accounts, no cookies, no tracking. The code is open source under the MIT License. You can <a href="https://github.com/marmot7775/dns-security-auditor" target="_blank" rel="noopener">read it, run it locally, or fork it</a>.</p>
    <section class="dbis-section">
        <h2>Who built this</h2>
        <p>I'm Neil Anuskiewicz. I work on email deliverability and authentication from Eugene, Oregon, and have since the days when DKIM was new. At Proofpoint Professional Services I ran DMARC programs for more than 40 enterprise customers, taking them from p=none to enforcement without dropping legitimate mail. That is where most of the judgment in this tool comes from: what a real rollout breaks, and which failures are worth acting on. These days my clients are mostly small companies, MSPs, and startups on Google Workspace or Microsoft 365, and the job is usually the same one at smaller scale.</p>
    </section>
    <section class="dbis-section about-closing">
        <h2>If your audit turned up something</h2>
        <p>Some findings are a five-minute DNS change. Some are not, and the hard part is knowing which is which before you touch anything.</p>
        <p>If you want a second opinion, email me at <a href="mailto:neil@dns-audit.com">neil@dns-audit.com</a> with your domain. I'll look at the audit and tell you plainly whether it needs a consultant or just a careful hour of your own time. When it does need one, the work is scoped in writing before anything starts: what is wrong, what the change is, and what could break. You approve it, and we make the change together. Longer work, like getting a domain with a dozen sending services to DMARC enforcement, is scoped the same way.</p>
    </section>

Then:

The meta description, og:description, and twitter:description at the top of about.html currently read "About dns-audit.com. Free open-source DNS and email security auditing tool. Built by Neil Anuskiewicz." Replace all three with: "Who built dns-audit.com and why, what it checks, and how to get a second opinion on what your audit found."

Check that `.about-closing` styling still applies now that it sits on a section rather than a div; adjust the selector if needed, no visual change intended.

Remove the LinkedIn and GitHub links from the old closing paragraph; they remain in the footer on every page.

## Part B: app output

### 1. Pluralization

result_transformer.py:4648, 4707, 4735, 4852: "Checked {tested} selectors", "Checked {tested} common selectors", "looked up {tested} common selector names", "Tested {tested} selectors". `tested_count` is 1 on the path where the user supplied a selector, so these render "1 selectors" and "1 common selector names", and "common" is wrong there because the name was the one the user typed.

Fix: one helper, for example `_sel = f"{tested} selector" + ("" if tested == 1 else "s")`, used in all four. Drop "common" when the selector came from the user: "Checked 1 selector, no public key found" and "This audit looked up the selector you supplied and found no public key at it."

pdf_report.py:191, 193, 194: cover prints "1 checks total", "1 issues", "1 warnings" on scoped runs. Pluralize each on its own count.

pdf_report.py:1503: "1 steps to reach RFC 9989 Ready status". Pluralize.

static/app.js:3216: share text "{failCount} issues". Pluralize; line 658 in the same file already does it right for the tab title.

static/app.js:1515: "1 problem found that only appear under strict RFC 9989 validation". The noun is pluralized, the verb is not. Make it "that appear" or "that appears" on the same count.

result_transformer.py:6909: "{active} active certificates" beside a verdict that already says "1 active cert". Pluralize and use the same noun as the verdict. result_transformer.py:6934: "Expiring in {days} days" with no lower bound, so "Expiring in 1 days" and "Expiring in 0 days". Use "Expiring today" for 0 and pluralize otherwise.

Add one test per surface (transformer, PDF text, app.js string) with a count of 1.

### 2. Four predictions about attackers, three of them near-identical

result_transformer.py:2392, 2637, 3057, 3109. "Attackers will use subdomains to bypass your policy", "Attackers will spoof subdomains like mail.yourdomain.com", "Attackers will target subdomains like mail.yourdomain.com", "attackers will spoof the root domain directly". The audit observed none of this. Two of them hardcode yourdomain.com when the audited domain is available in scope. And a reader who opens the card, the warnings panel, and the attack surface reads the same sentence three times.

Fix: say what is wrong and what it costs, once per surface, with the real domain. For 2392: " Your root domain is protected but subdomains are not, so mail claiming to be from a subdomain of {domain} is delivered as if the policy did not exist." For 2637 and 3057, the same shape with mail.{domain} as the example. For 3109: "np=reject is stricter than p=none, so invented subdomains are protected while the root domain is not. The root domain is the easier target."

### 3. The "Why does this matter?" paragraph

result_transformer.py:3488 to 3496. Opens with the "isn't just a technical checkbox" construction, has an appositive fenced by commas that parses as a list ("Recipients, your customers, partners, and employees, receive"), and ends in a 52 word sentence escalating to ransomware and data breaches with no evidence. It is the one paragraph on the surface written in marketing register.

Replace the content string with: "When your domain can be spoofed, someone else can send phishing and fraud that appears to come from you. Your customers, partners, and employees see your name on it. That costs you twice: the recipients who were fooled, and the sending reputation you need for your own mail to reach inboxes. RFC 9989 closes gaps RFC 7489 left open, particularly around non-existent subdomains and inconsistent receiver behavior."

### 4. Banned words and a contradictory impact line

result_transformer.py:440: "No urgent risks found. See the roadmap below for optimization opportunities." This is the biggest-risk line on every clean report. Replace with: "No urgent risks found. The roadmap below lists smaller improvements."

checks_extra.py:1071 to 1072: the BIMI oversized-logo finding says the file "may cause delivery issues" in the issue text and "slow down email rendering" in the impact line, and the fix says "Optimize the SVG". The logo is fetched by the mailbox provider, not carried in the message, so rendering speed is the wrong axis. Impact: "Some mailbox providers will not fetch a logo this large, so it may not display." Fix: "Reduce the SVG below 1MB. Removing embedded raster images and unused paths usually does it."

### 5. Hyphen

static/app.js:3760: "five minute DNS change" reads better as "five-minute DNS change". Apply the same to the About copy in Part A ("a five-minute DNS change").

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js changes.
Commit to a branch, push, merge to main, then deploy per CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-32.md in the same commit.

## Done when

The About page ends with an email address and a sentence about what happens when someone writes, no generated string prints a plural noun for a count of one, no card predicts what attackers will do, and the RFC 9989 explainer paragraph reads like the rest of the site.
