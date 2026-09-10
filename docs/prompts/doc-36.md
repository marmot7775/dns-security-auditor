# Doc 36: one header on every page

The site header differs between pages. static/index.html and static/404.html use a plain text wordmark, `dns<span class="logo-accent">-audit</span>.com`, with no terminal logo. static/about.html, static/privacy.html, static/articles/index.html, and the three article pages use the terminal window logo (`.logo-terminal` with the titlebar dots and the `$ dns-audit --dmarc` command line) followed by the wordmark `<span class="logo-accent">dns</span>-audit`. So a visitor moving from the homepage to About sees a different brand mark, a different spelling, and the accent colour on a different word.

Line numbers are from main at 3967857.

## Fix

Make the header markup identical on all eight pages, using the About page version (static/about.html, the `<header class="site-header">` block from line 38 to the closing `</header>`) as the source: terminal logo, then the wordmark `<span class="logo-accent">dns</span>-audit`, then the nav with Home, Articles, About and the theme toggle. The only per-page difference is which nav link carries `nav-link-active`.

Apply to static/index.html (header at line 137 onward) and static/404.html (line 19 onward). Check the other six for any drift in the nav wrapper (`header-right` is present on About and absent on the homepage) and make them match too.

Verify at 390px and 1280px in both themes that the terminal logo fits beside the nav on the homepage without wrapping, the same way it already does on About. If the existing `.logo-terminal` responsive rules at style.css 3376 and 4262 handle it, no CSS change is needed.

Add a test that extracts the `<header>` block from every static HTML page, normalises the `nav-link-active` attribute, and asserts all eight are byte-identical, so the header cannot drift again.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md only if style.css changes.
Commit to a branch, push, PR, wait for CI, merge to main, deploy per CLAUDE.md, confirm /api/health reports the new SHA.
Save this doc as docs/prompts/doc-36.md in the same commit.

## Done when

Every page shows the same logo, the same wordmark, and the same nav, and a test holds them identical.
