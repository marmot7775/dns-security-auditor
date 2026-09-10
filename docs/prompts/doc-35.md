# Doc 35: palette and type, Phases 1 and 2

This is the Phase 1 and Phase 2 proposal from the 2026-09-10 design review, adopted by Doc 34 Part B. Phase 3 (identity and layout) is deliberately not included.

## Where it stood

The site was accessible, consistent-ish, and clearly not broken. But it did not look distinctive, which is the gap between "competent" and "stunning":

- The palette was stock Tailwind. Slate greys (#0f172a / #1e293b / #334155), blue-500 accent, green-500 / amber-500 / red-500 status. It read as a template. Trust comes from a palette that looks chosen.
- It was flat. Card surface (#1e293b) barely separated from the ground (#0f172a); borders were the only depth cue. Dark mode looked washed, not deep.
- Three cool accents competed: blue (primary), teal (RFC 9989 badges), bright green (pass). On the results page the neon 9 / 3 / 0 counters were the loudest thing on screen; the verdict sentence was not.
- Under the hood, sprawl: 88 distinct hex colours in style.css against about 30 tokens; about 30 ad-hoc font sizes (0.65rem, 0.68rem, 0.72rem and so on) alongside the 7-step scale; base type at 15px with many labels rendering at 11px. Polish is mostly consistency, and this is where it leaked.

What was already good: dark-first with a proper light theme and toggle, AA-contrast work already done, self-hosted DM Sans and JetBrains Mono (variable fonts, DM Sans with an optical-size axis the CSS was not using), JetBrains Mono for records.

## Phase 1: type system

- Root 16px; every component font-size on the token scale (nothing below --font-xs, 0.75rem); two tokens added at the top (--font-3xl 1.75rem, --font-4xl 2.125rem) so display sizes have a home.
- font-optical-sizing: auto on body so DM Sans uses its display cut at heading sizes (already in the woff2, free).
- Headings at letter-spacing -0.02em.
- Keep DM Sans and JetBrains Mono. A font swap is the change most likely to be regretted after living with it; a disciplined DM Sans gets most of the way.

## Phase 2: palette

- One brand accent: a slightly desaturated cobalt (dark #5b8def links, #2f5fcc for surfaces carrying white text; light #2f5fcc) instead of blue-500. Teal stays for the RFC 9989 badges only.
- Status colours pulled off neon toward considered tones: pass #34c07a / #177245, warn #e0a43c / #9a5a10, fail #e5484d / #c93a3f (dark / light). The fail red rule in CLAUDE.md is updated with the new values and the reason.
- Deeper dark ground (#0b1220) with a clearer bg, surface, raised step; hairline borders one step up; softer, larger shadows. Light ground warmed slightly off pure slate (#f4f6f9).
- pdf_report.py colour constants mirror the light-theme tokens so the PDF matches the site.

## Constraints held throughout

AA 4.5:1 for every text and status colour on every surface it sits on, in both themes, enforced by tests/test_doc35_palette_contrast.py, which also holds the two light-theme token blocks identical and the PDF constants in step with the tokens. 44px touch targets. Self-hosted fonts only (the CSP blocks Google Fonts). No em dashes. Cache-bust per CLAUDE.md.

## Not in this doc

Phase 3: the terminal-window logo as the brand mark everywhere including the homepage header; a hero with a restrained signature and something under the input so the fold is not empty; a results hierarchy where the verdict is the headline and the counters are demoted to quiet pills. To be mocked and reviewed separately.
