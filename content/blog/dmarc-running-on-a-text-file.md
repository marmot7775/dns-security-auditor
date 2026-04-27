---
title: "Your DMARC Record Has Been Running on a Text File. You Did Fine."
description: "DMARC was never officially a standard. The deliverability community made it the floor of email security anyway. Now the spec is catching up. Here is what changed, and why you are not behind."
author: "Neil Anuskiewicz"
date: 2026-04-26
tags: [dmarc, dmarcbis, email-security, deliverability, infrastructure]
canonical_url: "https://dns-audit.com/blog/dmarc-running-on-a-text-file"
---

# Your DMARC Record Has Been Running on a Text File. You Did Fine.

DMARC, the email authentication standard that decides whether hundreds of millions of messages reach the inbox each day, has been depending on a list maintained by volunteers on GitHub.

I am not exaggerating for effect. The list is called the [Public Suffix List](https://publicsuffix.org/). It is a Mozilla project from 2007 that contains every public domain suffix on the internet. Volunteers maintain it. Receivers download copies and use them to figure out where your organizational domain ends, which is the load-bearing decision that determines whether your DMARC policy applies to a given message.

DMARCbis, the upcoming update to the DMARC specification, replaces this with a mechanism called the DNS Tree Walk.

I want to be clear about something. The volunteers are the heroes of this story.

They have kept this thing alive for nearly twenty years. They have processed thousands of submissions from registries adding new TLDs, from companies declaring private suffixes, from the long tail of internet weirdness. They have done it for free. They have done it well.

> For the last ten years, the load-bearing decision in DMARC has been made by consulting a list maintained by volunteers.

The absurdity is not the volunteers. The absurdity is that DMARC has been resting, structurally, on a list it does not own and volunteer labor it does not pay for, the entire time.

## You have been making this work anyway

Here is the part of the story I want you to feel.

DMARC was technically optional. RFC 7489 was published as an Informational document in 2015, which is IETF for "we are describing how this works, we are not asserting anyone has to do it this way." Vendors could implement it however they wanted. They mostly did not have to implement it at all.

But you did. Or someone in your industry did. Or a customer of yours pushed for it. Or your CISO read about a phishing incident and asked. Or Google and Yahoo announced their [2024 sender requirements](https://blog.google/products/gmail/gmail-security-authentication-spam-protection/) and suddenly bulk mail without DMARC was getting bounced at the front door.

The deliverability community spent ten years turning a Informational RFC and a volunteer-maintained text file into the actual floor of email security. Not because the standard required it. Because the people doing the work decided it should.

There is a M3AAWG mailing list that has been having the same conversations since the early 2010s. There are deliverability conferences where operators compare notes on how Gmail interpreted `pct=50` last week versus how Yahoo did. There is an entire informal apprenticeship system in this industry where senior practitioners teach junior practitioners how to read aggregate reports and triage alignment failures, none of which is documented in any RFC because none of which is the RFC's job.

You are part of that. Whether you know it or not. If you have a DMARC record at `p=reject` today, the reason it works is not because RFC 7489 is well-written. It is because thousands of operators figured out how to make it work despite RFC 7489 being incomplete, and because a few hundred volunteers kept the PSL fresh enough that the receivers could parse your record correctly, and because Gmail and Yahoo decided in 2024 that they were tired of waiting and made the standard mandatory by fiat.

The protocol caught up to the practice. Not the other way around.

## The fix is here. It is not clever.

DMARCbis, the long-awaited update to RFC 7489, will pull the PSL out of the protocol entirely.

What is replacing it? They are going to use DNS.

Yes. The DNS-based protocol is going to use DNS to answer a DNS question. Walk up the domain one label at a time, ask each level if it has a DMARC record, stop when you find one or hit eight levels deep. That is the entire upgrade.

If you are wondering why this took six years of working group meetings and forty-one drafts of the core specification, you are asking the right question. I do not have a satisfying answer. "Just use DNS for the DNS question" is the kind of obvious-in-retrospect fix that engineering teams need permission to ship, and it took the IETF a decade to give itself that permission.

What matters is that the fix is here. It is simple. It works. The receivers will start using it as soon as the spec publishes, which is currently blocked on the failure-reporting document that is on revision twenty-four and still being argued about. Final RFC publication is expected sometime in 2026, possibly into 2027, and the audit tools will catch up over a year or two after that.

You do not need to do anything dramatic. The DMARC record you have today still works. The PSL is not going anywhere overnight. The transition will happen in the background, mostly invisible to you, the way internet transitions usually do.

## What you actually need to do

If you want to be ready for DMARCbis, the work is small.

Drop the deprecated tags. The `pct=`, `rf=`, and `ri=` tags are going away. Most of them never worked consistently anyway. If your record has them, remove them.

Make sure your reporting URIs start with `mailto:`. The new parser is stricter than the old one. Bare email addresses that worked in 2018 will fail.

Add `psd=n` to declare you are not a public suffix. You are not, unless you are running a TLD registry, in which case you have bigger questions than this article.

Consider `np=reject` if you are already at `p=reject`. It closes the non-existent subdomain spoofing gap, which is a real attack surface. Audit your sending infrastructure first if you have third parties using subdomain branding.

Check that your external reporting destinations have authorization records. If your `rua=` points to a third-party DMARC processor, the destination domain needs to publish a record at `<your-domain>._report._dmarc.<destination-domain>` containing `v=DMARC1`. Without it, your reports go nowhere and you do not know.

That is the list. Five edits. Maybe ten minutes if your DNS is at a competent provider.

If you want to see exactly which of these apply to your specific record, run [dns-audit.com](https://dns-audit.com) on your domain. The audit shows you the current state, the DMARCbis-ready state, and the changes needed to get from one to the other. The DNS tree walk is animated, so you can watch the new algorithm walk your domain in real time and see exactly what receivers will see when DMARCbis publishes.

## What I want you to take from this

You have spent the last decade running production email security on a protocol that was technically not even a standard, depending on a text file maintained by volunteers, working around inconsistencies between receivers, and you made it work.

The IETF is going to publish a Standards Track RFC in 2026 or 2027 that formalizes most of what you have already been doing.

You are not behind. You are early. The new spec is paperwork catching up to operational reality.

When the audit tools start flagging `pct=` as deprecated, you will already know what to do because you have been getting those flags from your aggregate reports for years. When receivers start honoring `np=reject`, you will already understand the threat model because you have been arguing with your security team about non-existent subdomain spoofing since 2019. When the PSL finally gets pulled out of the protocol, you will not even notice, because you have been working around its quirks for so long they have become invisible.

The DMARCbis upgrade is real. The work to get there is small. The thing you should feel about all of it is not anxiety about being out of date.

It is something closer to pride that you and the people doing this work were running the actual standard the whole time, while the official one was still being written.

If you want the deep technical version with all the RFC numbers and the complete checklist, [I wrote a long piece on the technical state of DMARCbis](https://dns-audit.com/dmarcbis) that pairs with this one. That piece is the receipts. This piece is the reason the receipts matter.

The volunteers got us here. The operators kept it running. The IETF is finally writing it down.

You did fine.

Better than fine, actually. You did the hard part.
