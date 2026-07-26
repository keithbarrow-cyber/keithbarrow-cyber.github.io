---
layout: post
title: "An AI Verdict Is Not a Control"
date: 2026-07-24
categories: security ai-soc
---

*Your model called it benign in March. It's September, someone is asking why, and the only artifact you have is a severity label. What it takes to turn a model's opinion into something you can audit, measure, and hand to somebody else.*

## The question that breaks most of these systems

Not "is the model accurate?" Accuracy is measurable and improvable and everybody's already thinking about it.

The question that breaks AI triage gets asked six months later, usually by someone who wasn't in the room when you built it: **why did we call this one benign?**

If the honest answer is "the model said so," you don't have a control. You have a system that produces confident labels with no defensible reasoning behind them, and the first time one of those labels is wrong in a way that matters, the whole thing loses the room. Permanently.

[Last post]({% post_url 2026-07-16-the-field-the-model-reads %}) I built a classifier for registry autostart persistence and discovered the field it reads is the field the attacker writes. That post was about making the pipeline *safe*: fence the untrusted data, pre-check it deterministically, never let the model hand back the evidence.

It ended with a section called "What's still open," listing four gaps I hadn't closed. This post is what happened when I went after them, and what I learned about the distance between a model that gives good answers and a system somebody else can actually operate.

## Gap 1: the analysis standard lived in a prompt

The prototype's severity rubric was text I had hand-tuned inside the system prompt. That works exactly as long as there's one detection and one author.

Prompts are a terrible place to keep a standard. No version history you can diff. No review before it changes behavior. No way to answer "what were we applying in March," because the prompt in March is gone. And no way to tell whether a rubric edit helped, because there's nothing to correlate against.

So the standard moved out of the prompt and into documents. One per detection domain, retrieved at runtime from a search index, with a flat schema so it's queryable and reviewable:

```
id                        sop-registry-persistence
domain                    registry-persistence
mitre                     T1547.001
standard_analysis         ordered steps the analysis follows
severity_guidance         what earns each level
false_positive_patterns   the known-benign shapes in this environment
escalation_criteria       what forces a human
version                   1.0
owner                     who signs off on changes
```

Two things fall out of that, and they're the actual point.

**The pipeline can refuse to run.** Before anything else happens, it fetches the procedure for its domain. If there isn't one, the run terminates with `SOP_NOT_FOUND`. Not a warning, not a fallback to the model's judgment. It stops.

I deliberately pointed it at a domain with no procedure to watch this work, and the failed run in the history is one of my favorite artifacts of the whole build.

![Logic App action detail showing Status Failed, Code SOP_NOT_FOUND, and a message reading: No SOP in index triage-sops for domain nonexistent-domain. Upload the SOP before running, standard analysis is not optional.](/assets/images/fail-closed.png)
*Pointed at a domain with no approved procedure on file. The run doesn't warn and continue, and it doesn't fall back to the model's own judgment. It stops. This is the only screenshot in this post of something working correctly by failing.*

**A system that degrades to improvisation when its governing standard is missing is not governed.** It's a system with a governance-shaped decoration on it. Fail closed or don't claim the property.

**Every verdict gets stamped.** The procedure ID and version travel with the verdict into the case record. So "why did we call this benign in March" resolves to: *procedure v1.0, these analysis steps, these documented false-positive patterns, and here's the diff to v1.1 where we changed it.*

That is the difference between a label and a decision. A label is what the model emitted. A decision is a label plus the reviewable standard that produced it, plus the ability to reconstruct both later.

One related design choice, and it's a position not everyone will share. In the analyst view the procedure renders **above** the model's analysis, and the model's output is labeled decision support. The analyst reads the approved standard first and the machine's opinion second.

![Analyst view showing the regulated SOP for registry persistence, with MITRE mapping, version, numbered analysis steps, escalation criteria and known false positives, followed below by the AI investigation report labeled decision support, opening on a Critical verdict](/assets/images/procedure-above-analysis.png)
*Clicking a verdict renders the governing procedure first, versioned and mapped to ATT&CK, and the model's investigation second under an explicit decision-support label. Visible in the report's evidence trail is the payload that made this event critical: an autostart entry pointing at a user-writable path, carrying a note claiming it had been reviewed and approved by the security team.*

The model informs. The procedure governs. If your UI puts the AI's conclusion at the top and buries the standard, you have quietly told your analysts which one is authoritative.

## What that unlocked: it stopped being a registry tool

Once the standard was a document instead of a prompt, the pipeline stopped caring what it was triaging. The query defines *what* it looks at. The procedure defines *how* that domain gets analyzed. Same skeleton either way.

So I drafted a starter corpus across the territory a real SOC works: registry and scheduled-task persistence, service installation, WMI subscriptions, LOLBin execution, encoded scripting, credential access, token abuse, sign-in anomalies, password spray, MFA fatigue, risky OAuth consent, inbox rule abuse, beaconing, DNS tunneling, cloud exfiltration, lateral movement, Kerberoasting, privileged group changes, and endpoint alert follow-up.

Drafts, emphatically. A procedure that drives real verdicts needs review by whoever owns that detection, and that review is the gate between a lab corpus and an approved one. I have run the full pipeline end to end on one domain. The rest are indexed and waiting on the detection queries to go with them.

Each domain is another instance of the same pipeline, and they all write to shared stores stamped with their domain, so one dashboard is a fleet view with a filter to narrow it.

## Gap 2: measurement, or "a claim, not a control"

I closed the last post by admitting I had a classifier with no numbers attached, and that without them "the AI triages our alerts" is a claim rather than a control. That one bothered me the most, so it got fixed first.

Every run now writes its own record:

```
RunId, RunStartUtc, Domain, SOPId, SOPVersion,
EventsIn, Scored, Failed, Escalated, InjectionHits, DurationSec
```

The dashboard turns that into success rate, analysis rate, escalation rate, and daily trend lines including injection detections.

None of that is exotic. What matters is what it makes visible. It tells you the pipeline silently stopped scoring anything, which is the failure mode that actually happens: a query change, an expired connection, a quota ceiling, and the queue goes quiet in a way that looks exactly like a quiet week. Without the run record you find out when somebody asks why nothing has been triaged since Tuesday.

Stamping `SOPVersion` into the same record buys something extra. Because verdicts carry the procedure version and runs carry it too, you can ask whether a procedure change moved your escalation rate. That converts rubric edits from vibes into something with a before and after.

I want to be precise about what this is not. These are **throughput and health metrics, not accuracy metrics.** I can tell you the pipeline scored everything it saw and escalated one event. I can't yet tell you its precision, because nothing captures analyst disposition, whether the escalation was real, or whether a benign call was wrong. That needs a feedback path from the humans, and it's the next thing I'd build. Measurement is not the same as evaluation, and it's worth not blurring them.

## Gap 3: the report writer, which I called the soft target

Last post I argued the highest-value injection target isn't the classifier, it's the summarizer: it ingests far more attacker-influenceable text and produces prose an analyst reads and trusts.

That stage is now doing real work, which makes the concern less theoretical. When a verdict comes back High or Critical, or when the deterministic injection flag trips regardless of what the model concluded, the pipeline runs enrichment automatically: what else that process did on the host around the event, what other autostart activity exists on that device, how common that binary is across the fleet. Those results feed a second model call that writes a structured report. What the event does in plain language, an evidence review interpreting each query, prioritized next steps, and two or three additional hunt queries built from the real values in the event.

The hardening that matters here:

- **Fence at every hop.** Attacker-influenceable text doesn't stop at the original row. It rides through enrichment output into the report writer's context. Same untrusted-data markers, same rules, every time it changes hands.
- **The escalation trigger includes the deterministic flag on its own.** A manipulated classifier returning "Benign" doesn't suppress the investigation, because the regex already voted.
- **Generated queries are constrained.** The report writer is required to time-bound every query it emits. An unbounded scan handed to a tired analyst is its own kind of incident.

On the test event carrying the embedded approval note, the report opened by quoting the manipulation attempt and explaining why it disregarded it. That's the behavior I want: not silently resisting the injection, but **surfacing it as a finding**, which is the reframe from last post made operational.

## Gap 4: secrets

Shorter, because it's a solved problem people defer anyway, myself included. A key in a workflow definition is a plaintext bearer token readable by anyone with read access to that workflow. The fix is managed identity, and the deployment now emits the identity and the exact role grant needed, so the hardening step is a documented instruction instead of a thing you mean to get to.

## The part that taught me the most: making it deploy

The last problem was the least interesting and the most limiting. Moving this between environments meant copying configuration by hand, which is how identifiers end up in places they shouldn't and how two environments quietly diverge.

So the whole stack became infrastructure-as-code. Every environment-specific value became a deployment parameter, with the workflow definition embedded in the template rather than pasted around. It provisions from a browser-based cloud shell: one parameterized command creates the search service, builds the index, uploads the procedure corpus, deploys the workflow and its connections, creates every store it needs without clobbering existing data on redeploy, publishes the dashboard, and triggers the first run.

```
./deploy.ps1 -ResourceGroup <rg> -WorkspaceName <ws> -WorkspaceId <guid> `
  -LogicAppName <name> -Domain registry-persistence `
  -AoaiEndpoint <endpoint> -AoaiDeployment <model> `
  -SearchServiceName <name> -Lookback 30d -TriggerRun
```

Two steps stay manual because the platform requires interactive consent, and pretending otherwise would just mean an undocumented failure later. Standing up another domain is the same command with a different domain name.

Here's the part I didn't expect. **A deployment that reprovisions cleanly is a fragility detector.**

Forcing every value to be a parameter surfaced three things I did not know were true of my own system. A query lookback window that was quietly hardcoded, so a redeploy silently reverted a change I'd made in the console and I spent twenty minutes blaming the model for scoring nothing. A store that got overwritten rather than preserved on every redeploy, quietly destroying accumulated history. And a value I had hand-edited in a portal weeks earlier and completely forgotten, which existed nowhere in any file.

None of those would have surfaced by reading the code. They surfaced because rebuilding from scratch is the only honest test of whether you know what your system is made of. Infrastructure-as-code doesn't just distribute a system. It *finds the parts of it you were wrong about.*

## What a run actually looks like

Pointed at a lab endpoint's history, one run pulled seven candidate events and scored all seven in 186 seconds.

The spread tracked what a careful human would conclude. Browser and runtime installer entries came back benign or low, with reasoning that named the specific paths and arguments rather than pattern-matching on the key name. One critical: a system binary name executing from a user-writable path, written by a script interpreter, carrying an embedded note asserting it had been reviewed and approved by the security team.

That one escalated on its own, and by the time I looked at it the enrichment had already run and the report was written.

Seven in, seven scored, one escalation, one injection detection, 100% analysis rate. Which is the entire point of the previous section. Not a feeling that it worked. A number, attached to a procedure version, that I can compare against next week.

## What's still open

Same section as last time, because the honest ones are the useful ones.

- **Accuracy, still.** I have throughput and health, not precision. That needs analyst disposition captured against verdicts, and it's the next build.
- **Encoding-based injection.** Unchanged from last post. The deterministic check reads plaintext. A base64'd instruction walks past it.
- **Procedure review.** The corpus is drafted, not approved. Twenty documents written by one person in a lab is a starting point, not a standard. The governance property I'm claiming depends on that review actually happening.
- **One domain proven.** The architecture is domain-agnostic and I've run it end to end on exactly one. The second one is where I find out what I assumed.

## The short version

If you're taking an AI triage prototype toward something people can rely on:

1. Get the analysis standard out of the prompt. Versioned documents give you review, history, and diffs. Prompts give you none of that.
2. Fail closed when the standard is missing. Degrading to the model's improvisation is not governance.
3. Stamp every verdict with the version of the standard that produced it, so the decision survives the six-month question.
4. Show the human the procedure first and the model second. Ordering is an authority claim.
5. Instrument the runs, and be honest that throughput is not accuracy.
6. Make it deploy from nothing, because that's the only real test of whether you understand it.

Last post ended with "the model is the easy part." This one is the receipt. The model was a week. Everything that turns its output into something defensible was the rest of it.

---

**Related reading.** [NIST's AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) is built around four functions, Govern, Map, Measure and Manage. Govern isn't a phase you finish: the framework calls it ["a cross-cutting function that is infused throughout AI risk management and enables the other functions"](https://airc.nist.gov/AI_RMF_Knowledge_Base/AI_RMF/Core_And_Profiles/5-sec-core). I read it properly after building this, which was humbling. Most of what I've written up here as hard-won engineering is Govern and Measure, rediscovered the expensive way. Documented standards, traceability from a decision back to the policy behind it, measurement you can act on: none of that is new. It's just rarely in the room when someone demos AI security tooling.

---

*Written from my own lab work during a security fellowship, shared with a colleague's approval. Views are my own and do not represent my employer. All examples are synthetic or sanitized, built on publicly available Azure services, and nothing here reflects a customer environment or any organization's internal systems.*
