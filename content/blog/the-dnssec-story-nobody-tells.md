---
title: "The DNSSEC Story Nobody Tells"
description: "DNSSEC has a reputation problem the protocol no longer deserves. A January 2026 dialogue between an ICANN technologist and a humanities-trained newcomer surfaces the part of the story almost nobody tells."
author: "Neil Anuskiewicz"
date: 2026-04-26
tags: [dnssec, dns, dns-security, storytelling, infrastructure]
canonical_url: "https://dns-audit.com/blog/the-dnssec-story-nobody-tells"
---

# The DNSSEC Story Nobody Tells

In January, a researcher named Barbara Jantzen published a dialogue with Roy Arends, who has worked on DNSSEC at ICANN since the late 1990s.

The piece is called [The Excruciating Slow Rise of DNSSEC](https://circleid.com/posts/the-excruciating-slow-rise-of-dnssec). It is one of the strangest technical articles I have read in years.

It is strange because Jantzen is not a technologist. She is trained in the humanities. She came to the DNS world through a job at deSEC, a non-profit DNSSEC operator, and what she noticed was not technical. It was emotional.

People in the DNS community, she observed, had feelings about DNSSEC. Not opinions. Feelings. They were embarrassed by it. They were angry about it. Some of them, quietly, were heartbroken.

She was right. And the heartbreak is the part of the DNSSEC story almost nobody tells.

## A protocol that was supposed to save the internet

DNSSEC shipped in pieces between 1999 and 2010. Roy Arends was there for all of it. He was twenty-something when he started. He is in his fifties now.

In 2009, the year the first generic top-level domain was signed with DNSSEC, Arends thought the work was done. The math was right. The standards were ratified. The root zone was about to be signed. Adoption seemed inevitable. He moved on to the next thing.

Then a few years passed. Then a decade. And DNSSEC, somehow, was not winning. It was losing.

Outages happened. The IANIX outage list grew longer. Paul Vixie, one of the architects of the modern DNS, called DNSSEC a colossal flop in 2008 and the line stuck. In 2015, a security researcher named Thomas Ptacek published a blog post titled [Against DNSSEC](https://sockpuppet.org/blog/2015/01/15/against-dnssec/) that more or less ended the protocol's reputation in serious technical circles.

And then it just sat there. Not adopted. Not removed. Mostly mocked. A protocol that had been described, with a straight face in 2009, as the future of internet security.

If you spent fifteen years of your career on something and watched it become a punchline, how would you feel?

## The part where they laughed

Here is the moment in the Jantzen and Arends dialogue that I cannot stop thinking about.

Jantzen wanted to test whether the heartbreak was real. So she did something bold. She wrote a stand-up comedy talk about DNSSEC and performed it at the IETF, the standards body where most of these people work, at an evening event called the Bad Attitude Pecha Kucha.

She was nervous. She did not know if it would land.

It landed. The room laughed so hard that Arends, sitting in the audience, looked at the other DNSSEC engineers around him and saw it on their faces. "All the tech people around me, who basically were on the same path as I was since 2000, looked at each other in recognition. And yes, we were on the floor laughing."

The technical term for what happened in that room is **catharsis**. The colloquial term is **comic relief**. What Jantzen had figured out, and what Arends confirmed, was that the people who built DNSSEC had been carrying something heavy for years and nobody had ever named it.

This is what the dialogue makes clear, and what almost no piece of DNSSEC writing acknowledges: the protocol's reputation problem and its emotional history are the same problem.

## What this has to do with you

You probably have an opinion about DNSSEC.

It is probably some version of: complicated, fragile, a great way to take your domain offline at 2am. You read [Against DNSSEC](https://sockpuppet.org/blog/2015/01/15/against-dnssec/) once. You have probably referenced it in a Slack thread within the last eighteen months.

Here is what Jantzen's article forced me to admit. **My opinion of DNSSEC was formed in 2014. I never updated it.**

I would guess yours was too.

## The protocol that quietly got fixed

While the DNS community was busy being embarrassed about DNSSEC, the engineers kept working on it. They did not stop. They just stopped getting noticed.

In 2014, [RFC 7344](https://www.rfc-editor.org/rfc/rfc7344) introduced a way for DNS providers to publish key changes directly in the zone, eliminating the registrar handoff that had caused most of the outages. In 2017, [RFC 8078](https://www.rfc-editor.org/rfc/rfc8078) formalized how parents should pick those changes up. In July 2024, [RFC 9615](https://www.rfc-editor.org/rfc/rfc9615) closed the last loop, the part where you bootstrap DNSSEC for the first time without any existing chain of trust.

The 2am phone calls. The DS records out of sync with the registrar. The "DNSSEC took down our domain" outage stories that defined the reputation. Almost all of them traced back to operations problems that have now been fixed at the protocol level.

The DNSSEC you remember was a manual sport. The DNSSEC you can deploy now is, at any reasonable provider, a checkbox.

Cloudflare made it a checkbox. deSEC made it a checkbox. Route 53 made it a checkbox. Google Cloud DNS made it a checkbox. The .ch and .cz and .se ccTLDs have supported the automated handoff for years. The .bank and .insurance TLDs have nearly 50% adoption because the registries require it.

The problem is no longer the protocol. The problem is that nobody told you the protocol changed.

## The discourse that did not update

This is the part that connects the heartbreak to the present.

The reason your opinion of DNSSEC has not updated is not your fault. It is a media problem. Slow incremental improvement is the worst possible content for the internet to surface. "DNSSEC quietly got better between 2017 and 2024 thanks to a series of operational standards" is not a viral headline. Nobody wrote it. Nobody read it.

What stuck instead were the dramatic stories. The outages. The contrarian takedown. The IANIX list growing longer year after year. Even though the *cause* of those outages was being engineered out of the protocol, the *story* of those outages was the only thing the broader tech community ever saw.

Jantzen calls this the salience effect. Drastic and fearsome news is more memorable than slow steady improvement. So an entire generation of operators formed their DNSSEC opinions during the rough years and never had a reason to revisit them.

Arends and his colleagues kept doing the work. They just did it in a room nobody was watching.

## The part where I tell you what to do

I do not need you to deploy DNSSEC. The internet is fine. Your business is probably fine. Skipping it is, for many domains, a defensible call.

What I am asking is much smaller. **Update your priors.**

The DNSSEC you have an opinion about is not the DNSSEC that exists. The reputation is ten years stale. The deployment friction is mostly gone if you are at a provider that bothered to keep up. The protocol is not asking you to suffer for it anymore.

Read [Jantzen and Arends](https://circleid.com/posts/the-excruciating-slow-rise-of-dnssec). It is twenty minutes. It will change how you think about technical protocols, not just this one.

If you want the technical version, with current RFC numbers, threat model precision, and what good looks like in 2026, I wrote [a long piece on the technical state of DNSSEC](https://dns-audit.com/dnssec) that pairs with this one. That piece is the receipts. This piece is the reason the receipts matter.

And if you want to see what your own domain looks like under the current protocol, run it through [dns-audit.com](https://dns-audit.com). The animated tree walk shows the validation chain end-to-end. You will know in thirty seconds whether your DNS provider made the checkbox available to you, whether you flipped it, and whether the chain is actually intact.

Most domains discover one of three things: signed and clean, signed but broken at the registrar handoff, or unsigned because the provider never offered it. All three answers are useful. None of them are the answer you formed in 2014.

## The part Jantzen got right

Near the end of her dialogue with Arends, Jantzen quotes Joe Abley from Cloudflare. Abley is one of the engineers who has been at this for as long as Arends has. His line about DNSSEC is the one that finally let me let go of my old opinion: "It doesn't have to be universally useful to have succeeded."

DNSSEC was never going to be universal. The marketing in 2009 oversold that. The backlash in 2015 underbought it. The truth, twenty-five years after the work started, is in the middle. The protocol works. It does a specific job. It does that job better now than it ever has. The people who need it use it. The people who do not, do not. Nobody is keeping score, and the engineers who built it have stopped expecting anyone to.

That is a quieter ending than the one anyone wanted. It is also, I think, the one we have.

The DNSSEC story nobody tells is that the people who built it kept showing up after the world stopped paying attention. They fixed the operations. They wrote the automation. They published the bootstrap RFC last summer. They are still in the room.

That deserves at least a second look.

---

*If you have an old opinion of DNSSEC, please do not act on it without checking whether it is still accurate. Run a domain you care about through [dns-audit.com](https://dns-audit.com), [DNSViz](https://dnsviz.net/), or [Verisign's DNSSEC Analyzer](https://dnssec-analyzer.verisignlabs.com/). Read [Jantzen and Arends](https://circleid.com/posts/the-excruciating-slow-rise-of-dnssec). Then form a current one.*
