---
title: "DMARCbis Is Now RFC 9989. DMARC Ran on a Text File. The New Standard Brings It Home to DNS."
description: "DMARC has leaned on a volunteer-maintained Public Suffix List for a decade. RFC 9989 replaces it with a DNS tree walk. Here is what changed, and why you are not behind."
author: "Neil Anuskiewicz"
date: 2026-04-27
tags: [dmarc, rfc9989, dmarcbis, email-security, deliverability, infrastructure]
canonical_url: "https://dns-audit.com/blog/dmarc-running-on-a-text-file"
---

# DMARCbis is now RFC 9989

**DMARC ran on a text file. RFC 9989 brings it home to DNS.**

Your DMARC record has been depending on a list maintained by volunteers on GitHub. You did fine. Here is what changed, and why you are not behind.

DMARC, the system deciding whether hundreds of millions of messages reach the inbox each day, has leaned on a single, unlikely dependency: the Public Suffix List. The PSL is a Mozilla Foundation project from 2007 that catalogs every public domain suffix on the internet.

Receivers download it. They use it to answer a deceptively simple question.

**Where does your organizational domain end?**

That answer determines whether your DMARC policy applies. It is the load-bearing decision.

And for a decade, it came from a text file maintained by volunteers.

The remarkable part is not that this existed. It is that it worked.

Those volunteers tracked new TLDs, private suffixes, and the internet's edge cases, quietly and accurately, for free. They kept the system stable while everything around it scaled.

DMARC depended on something it did not own and could not guarantee. And it held.

## You made it work anyway

Here is the part that matters more than the mechanism.

RFC 7489 was not a Standards Track document. It was Informational. In IETF terms, that means it describes behavior without requiring uniform implementation.

Vendors had room to interpret. Some did.

But operators did not wait.

They implemented DMARC anyway. They compared notes, built tooling, debugged alignment failures, and taught each other how to read aggregate reports. Communities like the Messaging, Malware and Mobile Anti-Abuse Working Group turned a loose document and a volunteer list into the actual floor of email security.

Then the market closed the loop. Gmail and Yahoo enforced DMARC for bulk senders in 2024.

The protocol did not lead. Practice did.

If you have a DMARC record at `p=reject` today, the reason it works is not because the RFC was perfect. It works because operators made it work, because volunteers kept the list current, and because receivers converged on behavior over time.

You are part of that, whether you set the record yourself or inherited it.

## The fix is here. It is simple.

RFC 9989 removes the Public Suffix List from the critical path.

In its place is the DNS tree walk.

Instead of consulting a downloaded list, the receiver queries DNS directly. It starts at the exact domain in the message and walks upward one label at a time. At each step, it checks for a DMARC record. It stops when it finds one or reaches a defined limit.

That is the change.

A DNS-based protocol now uses DNS to answer its own question.

This did not come out of theory. It reflects ten years of production experience. The working group incorporated what operators learned in practice, including inconsistencies in PSL handling, unreliable behavior of deprecated tags like `pct=`, and gaps such as non-existent subdomain spoofing, which the `np=` tag addresses.

The IETF published the specification in May 2026 as RFC 9989, alongside RFC 9990 (aggregate reporting) and RFC 9991 (failure reporting). Together they obsolete RFC 7489 and RFC 9091. Adoption will be gradual. The Public Suffix List is not disappearing overnight. The record you have today continues to work.

## What you actually need to do

If you want to be ready, the work is small.

- **Remove the retired tags.** RFC 9989 removes `pct=`, `rf=`, and `ri=`. Most were never handled consistently.
- **Fix reporting URIs.** Make sure they begin with `mailto:`. The new parser is stricter.
- **Declare `psd=n`.** You are not a public suffix unless you run a registry.
- **Consider `np=reject`.** If you are already at `p=reject`, this closes the non-existent subdomain spoofing gap. Audit third-party senders first.
- **Verify external reporting authorization.** If `rua=` points to a third party, that destination must publish `<your-domain>._report._dmarc.<destination-domain>` with a value of `v=DMARC1`. Without it, reports silently fail.

That is the list. A handful of edits. Minutes, not days.

If you want to see exactly which apply to your record, run [dns-audit.com](https://dns-audit.com) on your domain. The audit shows the current state, the RFC 9989-ready state, and the path between them.

## What to take from this

For ten years, you have been running production email security on a protocol that was not formally a standard, with behavior that varied by receiver, and a parsing model that depended on a volunteer-maintained list.

And it worked.

RFC 9989 does not replace that work. It captures it.

The new specification folds a decade of operational reality into a Standards Track RFC. The DNS tree walk replaces the Public Suffix List. Deprecated edges are removed. Real gaps are closed. Parsing becomes stricter.

None of this changes what you have been doing. It refines it.

When tools flag `pct=` as deprecated, you will already know why. When receivers enforce `np=reject`, you will understand the risk it addresses. When the Public Suffix List fades from the protocol, you will barely notice.

The upgrade is real. The work is small.

The correct reaction is not urgency.

It is recognition.

The volunteers built the list. Operators made the system work. The IETF is writing it down.

You are not behind. You were early.
