---
title: "DNSSEC Stopped Being Hard. The Reputation Did Not Catch Up."
description: "The DNSSEC you remember does not really exist anymore. RFC 9615, automation, ECDSA, hosted signing. What changed, what it actually protects against, where it still falls short, and what good looks like in 2026."
author: "Neil Anuskiewicz"
date: 2026-04-26
tags: [dnssec, dns, dns-security, infrastructure, deliverability]
canonical_url: "https://dns-audit.com/blog/dnssec-stopped-being-hard"
---

# DNSSEC Stopped Being Hard. The Reputation Did Not Catch Up.

Look. You already have an opinion about DNSSEC.

It is probably some version of: complicated, fragile, a great way to take your domain offline at 2am. You read [Against DNSSEC](https://sockpuppet.org/blog/2015/01/15/against-dnssec/) once and bookmarked it. You have probably referenced it in a Slack thread within the last eighteen months.

You also have a story. Maybe yours, maybe a colleague's. There was a key rollover. There was a registrar. There was a 2am phone call from someone who was not you but whose problem suddenly was. The domain was down. The DS record was wrong. The recursive resolvers were validating, which two years earlier they were not, which made the whole thing your problem in a way it would not have been in 2012. Someone got a stern email. The Hacker News thread wrote itself.

That story is true. That story is also ten years old.

I am not going to tell you DNSSEC was secretly fine all along. It was not. The protocol shipped before the operations did, which is exactly the order you do not want to ship things, and an entire generation of DNS operators paid for that with their weekends. The skepticism in your inbox was earned. The [IANIX outage list](https://ianix.com/pub/dnssec-outages.html) was earned. Paul Vixie called it a colossal flop in 2008 and he was not wrong.

Here is what is also true.

The thing you are skeptical of is not really the thing that exists anymore. RFC 7344. RFC 8078. RFC 9615. CSYNC. Algorithm 13. ECDSA signatures that fit in a UDP packet without making your firewall sad. Cloudflare and deSEC and Route 53 quietly deciding to make DNSSEC a checkbox while the rest of the internet was busy not paying attention. The registrar handoff that used to ruin your Tuesday is, at any provider that bothered, automatic.

Most of this happened in the last six years. Most of it was boring. None of it generated a viral blog post called "Actually Maybe DNSSEC Is Fine Now," because nobody writes those, because slow incremental improvement is the worst possible content for the internet to notice.

So here is the deal. I am going to tell you what changed, what DNSSEC actually protects against (less than the cheerleaders claim, more than the haters admit), where it still falls short, and what good looks like in 2026. With receipts. RFC numbers. Provider names. The actual threat model, scoped honestly.

You are then free to keep your skepticism. I am not in the business of converting anyone. But I would rather you keep it for current reasons than ten-year-old ones.

Let me show you.

## What actually changed

If you tried DNSSEC before 2017 and gave up, you are not remembering wrong. You are remembering a protocol that genuinely was bad to operate.

The signing was fine. The math worked. The hard part, the part that broke everything, was getting your DS record from your DNS host into your registrar's web form and keeping it there through every key rollover. You logged into one panel, copied a string of hex, logged into another panel, pasted it, and prayed. If you rotated your KSK and forgot the parent registrar step, your domain went dark. Not slowly. Immediately. And not just for you, for every recursive resolver doing validation, which by 2018 was a meaningful chunk of the public internet.

That dance is over.

[RFC 7344](https://www.rfc-editor.org/rfc/rfc7344) (2014) introduced CDS and CDNSKEY records. Translation: your DNS host can now publish "here is my new DS record" directly in your zone, and the registrar can pick it up automatically. [RFC 8078](https://www.rfc-editor.org/rfc/rfc8078) (2017) formalized how parents should handle it. [RFC 9615](https://www.rfc-editor.org/rfc/rfc9615) (July 2024) closed the last loop, the chicken-and-egg of how you trust the very first DS record before any chain of trust exists. The bootstrap is now automatic for any provider that bothered to implement it.

That phrase, "any provider that bothered to implement it," is doing real work. We will come back to it.

Algorithm 13 also happened. ECDSA P-256, ratified in [RFC 6605](https://www.rfc-editor.org/rfc/rfc6605) back in 2012, dominant by the early 2020s. The practical effect is that DNSSEC signatures stopped being a fragmentation problem. RSA-SHA256 signatures could push DNS responses past the 1232-byte EDNS buffer and force fallback to TCP, which some networks blocked, which is where a lot of the "DNSSEC broke my domain" stories actually came from. ECDSA signatures fit comfortably in a UDP response. The packet-size objection was real in 2010. It is mostly a footnote now.

[CSYNC](https://www.rfc-editor.org/rfc/rfc7477) (RFC 7477) sits next to CDS doing the same job for NS and glue records. Different problem, same vibe: the child zone announces, the parent syncs, no human in the loop.

And then [RFC 9859](https://www.rfc-editor.org/rfc/rfc9859) added Generalized DNS Notifications, which means the parent does not have to poll. The child pings. Updates propagate in seconds instead of waiting on a refresh timer.

Add it up. The DNSSEC you remember required hands-on work at every step. The DNSSEC you can deploy now is mostly someone else's job. The skepticism you have was earned in an era that, technically, ended a few RFCs ago.

That is the gap. Most people's mental model of DNSSEC is frozen somewhere around 2015. The protocol kept moving. The reputation did not.

## What it actually protects against

Most DNSSEC posts will tell you it "secures DNS." That sentence is doing a lot of work, and most of the work is dishonest.

Here is what DNSSEC actually does. It signs DNS answers. When your resolver asks "what is the IP for example.com," DNSSEC lets it verify the answer came from example.com's zone and was not changed by anyone in between. Origin authentication. Integrity. That is the whole job.

That is not nothing. Cache poisoning is real. The Kaminsky attack from 2008 was real. On-path DNS tampering on coffee shop wifi, sketchy ISPs, and entire countries is real. If you have ever had DANE or SSHFP records do anything useful, DNSSEC is why they were not lies.

Here is what DNSSEC does not do, despite what some marketing copy implies.

It does not stop phishing. An attacker can register `paypa1.com`, sign it perfectly, and your validator will happily confirm the answer came from `paypa1.com`. DNSSEC has no opinion on whether you should have typed that URL.

It does not stop email spoofing. That is SPF, DKIM, and DMARC, all of which live above DNSSEC and have nothing to do with it.

It does not encrypt your DNS queries. That is DoH and DoT. Different protocol, different problem, often confused.

It does not protect against an attacker who compromises your DNS provider's signing infrastructure. They can sign whatever they want.

It does not protect against an attacker who hijacks your domain at the registrar. They can change the DS record.

The honest pitch is narrower than the marketing pitch and stronger because of it. DNSSEC closes a specific class of DNS-layer attacks that no other protocol closes. If you do not deploy it, you are trusting every resolver and every network between you and your authoritative server to be honest. Some of them are not.

## Where it still falls short

This is the section most DNSSEC posts skip. The protocol got better. The deployment landscape did not, evenly.

DNSSEC adoption is currently around 4.3% of all registered domains, per [recent data](https://dnschkr.com/blog/dnssec-adoption-2026) from February 2026. Up from roughly 1% in 2017. Genuine progress, also genuinely modest. The story under that number is more interesting than the number itself.

Think back to HTTPS adoption a decade ago.

Site operators did not wake up one morning and decide they wanted TLS certificates. They had been told for years that HTTPS was important. Most of them filed it under "yes, eventually." Then Let's Encrypt happened, and Cloudflare flipped TLS on by default, and the hosting providers started auto-provisioning certs at signup, and the question stopped being "do you want HTTPS?" and started being "do you even know whether your site is on HTTPS?" The answer for most operators was that their provider had quietly turned it on while they were not looking.

DNSSEC is in the early innings of the same transition. The providers who automated it have high adoption among their customers. The providers who did not, do not. Adoption is not a domain owner decision. It is a provider decision, and the domain owner mostly finds out which side of it they are on after the fact.

Look at where DNSSEC is and is not deployed. The .bank TLD sits at 49.9%, because fTLD Registry Services requires it. The .insurance TLD sits at 49.2%, same reason. Google's .page sits at 35.7%, because Google handles signing automatically for every registrant. OVH's .ovh sits at 38.7% for the same reason.

Now look at the bottom. .top is at 0.34%. .xyz is at 0.87%. .shop is at 0.21%. These are not TLDs where DNSSEC is harder. They are TLDs where the registrars do not enable it by default and the customers never knew to ask.

What this means for you, practically:

If your DNS is at Cloudflare, deSEC, Route 53, NS1, or Google Cloud DNS, you can have DNSSEC in about 90 seconds. Click a button. Done. The provider handles signing, key rollover, and DS record submission to the registrar (assuming the registrar supports CDS scanning, which most major ones now do).

If your DNS is at GoDaddy on a budget plan, at Namecheap's BasicDNS, at most cPanel-hosted setups, or at any registrar that does not list DNSSEC as a feature: you have a problem. Not a hard problem. A "you may need to switch DNS hosting" problem. That is real friction, and the article you are reading would be lying to claim otherwise.

If your TLD is `.com`, `.net`, `.org`, `.io`, `.dev`, `.app`, or any major ccTLD, the registry side is fine. CDS scanning works. The bottleneck is your registrar, not the registry.

If your TLD is one of the long tail with weak DNSSEC support, the bottleneck is the registry. There are still TLDs where automation is incomplete, and you should check before assuming. The IANA's [TLD DNSSEC report](https://www.internic.net/domain/) is the canonical reference.

The honest summary: if you are at a major DNS provider on a major TLD, deploying DNSSEC in 2026 is a checkbox. If you are not, you may need to migrate something before the checkbox is available to you. The protocol is no longer the bottleneck. The provider lottery is.

You can run [dns-audit.com](https://dns-audit.com) on your domain to see where you actually stand: chain status, algorithm in use, whether your provider is publishing CDS/CDNSKEY, and whether your registrar is picking them up. The animated DNS tree walk shows the validation chain end-to-end. Most domains discover one of three states: signed and clean, signed but broken at the registrar handoff, or unsigned because the provider does not support it. All three answers are useful.

## What good looks like

You can tell within thirty seconds whether someone deployed DNSSEC well or just deployed DNSSEC.

Bad DNSSEC is signed. Good DNSSEC is signed and survives Tuesday.

Here is the difference.

**Algorithm 13.** ECDSA P-256, [RFC 6605](https://www.rfc-editor.org/rfc/rfc6605). Not RSA-SHA256, not RSA-SHA1, definitely not whatever your DNS provider was defaulting to in 2014. ECDSA signatures are small enough to fit in a UDP response without provoking your network's most paranoid middlebox. RSA-SHA256 still works, but every byte you save on signature size is a byte not pushing you toward TCP fallback, and TCP fallback is where DNSSEC outage stories come from. If you are signing fresh in 2026 and your provider is offering RSA, ask why.

**Automated key rollover via CDS and CDNSKEY.** RFC 7344 and RFC 8078. If your DNSSEC deployment requires a human to copy a DS record from one panel to another, you do not have a DNSSEC deployment, you have a future incident with a date attached. The whole point of the last decade of DNSSEC standards work was making this part go away. Make it go away.

**A monitored DS record at the registrar.** Not a one-time check. Continuous. Because the failure mode of DNSSEC is not "wrong key," it is "key that used to be right." If your DS record drifts out of sync with your zone, your domain goes dark for every validating resolver, which by now is most of them. Pingdom does not catch this. Most uptime monitors do not catch this. You need something that actually validates the chain.

**End-to-end validation tested, not assumed.** Run [DNSViz](https://dnsviz.net/) on your domain. Run [Verisign's DNSSEC analyzer](https://dnssec-analyzer.verisignlabs.com/). Run [dns-audit.com](https://dns-audit.com). All three will tell you whether your chain of trust is actually intact from root to your zone, or whether you have a quiet break that will become loud the moment a recursive resolver upgrades its validation strictness. ICANN's KSK rotations have caught more than a few operators flat-footed this way. You do not want to be one of them.

**Hosted, not hand-rolled.** Unless you are running DNS for a registry, a TLD, or a national CERT, you should not be running your own signers. Cloudflare, deSEC, Route 53, NS1, and a handful of others operate signers at a scale and reliability you cannot match in-house, and they are the ones who paid to make RFC 9615 actually work in production. Use them. The old "we run BIND with custom scripts" energy is how outages happen.

**A KSK rollover plan you have actually rehearsed.** Once. Just once. Most operators have never rolled their KSK, which means the first time they do it, it will be in production, under pressure, with a registrar interface they have not looked at in three years. Pick a quarter. Do a rollover. Take notes. Now it is muscle memory.

**Algorithm rollover capability.** Less urgent, but on the radar. The post-quantum conversation is happening in IETF working groups right now, and at some point in the next decade you will need to migrate algorithms. The infrastructure to do that without an outage is the same infrastructure that handles routine KSK rollovers. If you can do one, you can do the other.

That is the bar. Most domains that "have DNSSEC" are signed, and that is roughly where the work stopped. Signed is the floor, not the ceiling. The ceiling is signed, automated, monitored, hosted, validated, and rehearsed. Anything less is a domain that works until it does not.

## The closer

Here is the part where most posts about DNSSEC tell you to deploy it because deployment numbers must go up, or to skip it because deployment numbers prove it failed. Both takes are bad. Both treat DNSSEC like a cause.

DNSSEC is not a cause. It is infrastructure.

You enable it where it makes sense. You skip it where it does not. You stop tracking your worth as an operator by whether your domain shows up green on a public dashboard. Joe Abley said it cleanest, in the [CircleID dialogue](https://circleid.com/posts/the-excruciating-slow-rise-of-dnssec) with Roy Arends earlier this year: it does not have to be universally useful to have succeeded. The version of success where every domain on Earth signs by 2030 was always a fantasy. The version where DNSSEC is reliably available to operators who need it, and quietly works when they turn it on, is achievable now and largely already achieved at the providers who bothered.

So if you are running a bank, a registrar, a CA, a software update channel, a government domain, anything where a DNS hijack ends up on a regulator's desk: deploy it, deploy it well, deploy it to the bar above. The threat model is real and nothing else closes it.

If you are running a marketing site, a personal blog, or a domain that mostly redirects somewhere else: sign it if your provider makes it a checkbox, skip it if they do not. The threat model does not justify migrating DNS hosting for a brochure site, and you do not need to feel bad about that call.

What I want you to stop doing is repeating ten-year-old talking points like they are current. The "DNSSEC is too complicated" line was true in 2014 and is mostly false in 2026 if you are at a competent provider. The "DNSSEC doesn't even encrypt anything" line confuses the threat model with someone else's threat model. The "nobody uses it" line ignores that the people who need it most are quietly using it and you just do not hear from them, because their domains are not on fire.

Update your priors. Read the [CircleID dialogue](https://circleid.com/posts/the-excruciating-slow-rise-of-dnssec). Read [SIDN's DNSSEC explainer](https://www.sidn.nl/en/modern-internet-standards/dnssec). Run [dns-audit.com](https://dns-audit.com), [DNSViz](https://dnsviz.net/), or [Verisign's analyzer](https://dnssec-analyzer.verisignlabs.com/) on a domain you care about and see what the chain actually looks like. Then decide.

That is the whole pitch. Not "deploy DNSSEC." Just: form a current opinion.

The 2015 one has had its run.

---

## Further reading

- [The Excruciating Slow Rise of DNSSEC](https://circleid.com/posts/the-excruciating-slow-rise-of-dnssec), Barbara Jantzen and Roy Arends, CircleID, January 2026
- [Why DNSSEC Is Still Failing: Lessons from 240 Million Domains](https://dnschkr.com/blog/dnssec-adoption-2026), DNSChkr, February 2026
- [SIDN's DNSSEC explainer](https://www.sidn.nl/en/modern-internet-standards/dnssec), the most thorough practitioner reference online
- [For DNSSEC and Why DANE Is Needed](https://blog.technitium.com/2023/05/for-dnssec-and-why-dane-is-needed.html), Technitium, May 2023
- [RFC 9615](https://www.rfc-editor.org/rfc/rfc9615), Automatic DNSSEC Bootstrapping (Thomassen and Wisiol, July 2024)
- [RFC 7344](https://www.rfc-editor.org/rfc/rfc7344), Automating DNSSEC Delegation Trust Maintenance (2014)
- [RFC 8078](https://www.rfc-editor.org/rfc/rfc8078), Managing DS Records from the Parent via CDS/CDNSKEY (2017)
- [RFC 6605](https://www.rfc-editor.org/rfc/rfc6605), ECDSA for DNSSEC (Algorithm 13, 2012)
- [RFC 7477](https://www.rfc-editor.org/rfc/rfc7477), CSYNC (2015)
- [RFC 9859](https://www.rfc-editor.org/rfc/rfc9859), Generalized DNS Notifications
