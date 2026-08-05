---
layout: post
title: "Nine Flags, Zero Lies"
date: 2026-08-02
categories: security ai-soc governance
---

*I built a check that forces an AI triage system to name the evidence behind every sentence it writes, then verifies every claim against the record with code. It fired nine times in two days. Nine out of nine, the model was telling the truth and something I had written was wrong. One of the nine was the checker itself.*

## Everyone is worried about the wrong failure

Ask anyone what goes wrong when you put a language model in front of security alerts and you'll get the same answer: it makes things up. Confident prose, invented details, a verdict that reads beautifully and is not connected to anything.

That is a real risk. It is not the one that bit me.

[Last post]({% post_url 2026-07-24-an-ai-verdict-is-not-a-control %}) I moved the analysis standard out of the prompt and into versioned, owned documents, so a verdict could be traced back to the exact text that produced it. That closed the question of *which rule applied*. It left a different question wide open, and a skeptical engineer finds it in about ten seconds:

**How do you know the model actually read the record?**

The procedure is versioned. The verdict is stamped. The reasoning is three tidy sentences that sound entirely reasonable. And nothing anywhere has checked whether a single word of it corresponds to the alert it was supposedly about.

This post is what I built to close that, what it caught, and why the answer changed how I think about where the risk in these systems actually lives.

## Make it name the field it read

The fix is not a better prompt or a second model grading the first. It is a change in what the model is required to return.

Alongside the verdict and the reasoning, it now has to emit a list of claims. Each one names a field of the record, the exact value it read from that field, and the statement that value supports:

```json
{
  "verdict": "No violation",
  "reasoning": "The rule matched because the file carries no sensitivity label...",
  "claims": [
    { "claim": "The match was not on content",
      "field": "MatchedOnContentSit", "value": "false" },
    { "claim": "The rule was not enforcing",
      "field": "AllRulesSimulation",  "value": "true" }
  ]
}
```

Then, after the model has answered and before anything is accepted, code walks that list and compares each cited field and value against the record the model was actually handed. Not another model. Code. A deterministic string comparison in the workflow engine.

**A model asked to audit its own honesty is not a control.** It is the same system marking its own homework, and it will pass. The whole value here comes from the check being mechanical, boring, and outside the thing it is checking.

Three details in it are deliberate, and each exists because the obvious version would have been useless.

**The comparison is case insensitive.** A model writing `High` where the record says `high` is not fabricating anything. A check that cried wolf over casing would be switched off inside a week, and a switched-off control is worse than no control because everyone still believes it is running.

**A cited field that does not exist fails.** That is the point rather than an edge case. Inventing a plausible field name is the single clearest signal that a model is reasoning about a record that was never in front of it.

**Only the fields the model was actually given are checkable.** Identity, file names and raw prompt text are withheld from the prompt for privacy reasons. Because they were never sent, a claim about one of them cannot be grounded and will not be accepted. The privacy control and the honesty control reinforce each other rather than trading off, which is rarer than it sounds.

And when a claim fails, the verdict is not discarded and it is not accepted. The model's exact words are kept, the specific claims that did not match are recorded, and the working verdict is forced to *Requires investigation* so a person sees it.

Here is what a rejection actually looks like, recorded against the verdict it stopped:

```json
[{ "claim": "No external recipients were recorded for this event.",
   "field": "AnyExternalRecipient",
   "value": "null" }]
```

**Coercing toward review rather than toward closure is the entire design.** The failure mode of a broken model must never be silent approval.

![Triage console. A list of incidents on the left, each led by a pseudonymous actor and the procedure that judged it. On the right, an open verdict of Violation confirmed with its written reasoning, the recommended next step, and a provenance block reading procedure sop-irm-departures v0.1 and fields cited 6, every one matched the record. Below that, buttons to agree or record a different verdict.](/assets/images/verified-verdict.png)
*Fields cited, every one matched the record. That line is the difference between reasoning you can read and reasoning you can check. The agree control underneath is the other half of this post: it is where the answer key comes from.*

## Nine flags, zero lies

I ran it across roughly 150 alerts exported from a working tenant. It fired nine times, across five distinct causes.

Zero of them were fabrications.

![Log Analytics results grid, nine rows, all from the DLP external-sharing procedure, all with a raw verdict of No violation. Each row shows the number of claims the model made and how many could not be verified. Four rows cite the same field, AnyExternalRecipient, with the value null. The others cite UniqueCount, SensitiveInformationTypeName, MatchedPolicies twice, and AllRulesSimulation with the value false.](/assets/images/ungrounded-claims.png)
*Every flag the check has ever raised. Nine claims across five causes, and not one of them is the model inventing anything. Four are a field I computed as null instead of false, four are values nested where a citation cannot reach them, and the last one is my own comparison turning false into an empty string.*


**Four were a boolean with three states.** A field meant to answer "were there any external recipients" was computed as `array_length(recipients) > 0`. For file-sharing events, which carry no recipients at all, that whole expression evaluates to null rather than false. So the model was handed a yes-or-no field whose value was neither. It read the field honestly, reported the value as null, and my check had no way to distinguish that from an invented one.

The model was right. My query was wrong. Nobody reviewing that query had spotted it, including the person who wrote it.

**Four were structure.** Two cited values buried inside a nested object, and two cited one element of an array that stringifies with its brackets, so a correct value could never match. A field named for a list of type names was actually shipping entire objects, several levels deep, including counts the model wanted and could see. It read those values correctly, cited them by their leaf names, and got rejected because the check resolves top-level keys only.

That one taught me a rule I would not have arrived at by reasoning: **a payload whose claims are meant to be checkable has to be flat.** Nesting lets a model be honest and still fail verification, which trains people to distrust the verifier rather than the model. Exactly backwards.

**And one was the checker being wrong.** The model reported a boolean as `false`, which was correct. My comparison ran the record's value through a coalesce that turns `false` into an empty string before comparing, so a true statement about a false field could never pass. Every payload here is full of booleans, so that one flag was the visible edge of a check that would have quietly rejected honest reasoning forever.

That is the one I think about most. I built an instrument to catch a model lying and the instrument itself was the thing making false accusations, and it took a real run against real data to notice. **Nothing about the code looked wrong.**

All of them are now fixed, and the fix to the nesting one was itself informative. The model had been reaching for a count of how many sensitive items were involved, because that is genuinely the thing that separates one credit card number from six hundred. It could not cite it, so it invented a path to it. **The check told me what evidence the procedure actually needed.** That was not what I built it for and it might be the most useful thing it does.

Worth saying what the check costs, since a post about showing numbers should show that one. Requiring claims lands at roughly 1,650 input and 330 output tokens per assessment, and the claims are a small slice of that output. Verification is close to free. The expensive part is the record and the procedure, which you were sending anyway.

## The one that actually scared me

Two days in, a run reported that it had found ten alerts and produced nine verdicts.

Every model call succeeded. The detection query was fine. One record had simply ceased to exist. No verdict row, no error, no note. Nothing except a discrepancy between two numbers.

The cause was a schema I had written on the model's response, declaring that every claim's value was a string. The model reported a count as the number `4` rather than the string `"4"`. Schema validation failed, the iteration died, and the alert vanished.

**A control I added for tidiness deleted the thing it was inspecting.**

Sit with that for a second, because it is the worst behavior anything in this system can have. Every other failure path fails closed: off-vocabulary verdicts, ungrounded claims, refused runs, throttled model calls. All of them write down what happened and route to a human. That one failed silent, and it failed silent inside a system whose entire pitch is that decisions are recorded.

The types are gone now rather than corrected, for two reasons. The model call already requests JSON output, so the response is guaranteed parseable and a schema could only ever add ways to fail. And real validation happens twice downstream anyway, in the vocabulary check and the grounding check, both of which fail closed.

The rule I took from it: **validation that can destroy its subject is not validation.** If a check cannot explain what it rejected, it should not be able to reject anything.

## The only reason I found it

The pipeline counts what each run found before any model is called, and counts verdicts by joining them back to their run afterwards. It never increments a counter as it goes.

That sounds like a fussy distinction. It is the difference between a system that can lose records and a system that can lose records *invisibly*.

![Run history table. Each row shows a procedure, its lookback window, how many incidents the query found, how many were judged, and the difference. Three rows show gaps: 78 found and 70 judged, 49 found and 40 judged, 8 found and 5 judged. Later rows for the same procedures show 78 and 78, 8 and 8, with a gap of zero.](/assets/images/run-gap.png)
*The top half is the system losing records. The bottom half is the same procedures after the causes were fixed. Nothing else in the pipeline reported a problem in either state, and every one of those runs completed successfully.*

That one design choice caught three separate classes of silent loss in two days: model calls exhausting their retries against a rate limit, ingestion lag being mistaken for missing data, and the validator above. None of them announced themselves. All three showed up as one number not matching another.

**If your AI pipeline cannot tell you the difference between a quiet day and a broken query, it cannot tell you anything.**

## So how accurate is it?

This is where the post gets less satisfying, and I think the honest version is more useful than the number you were expecting.

I do not know. Neither does anyone else selling you one of these, and here is why.

To measure whether an automated verdict agrees with a human, you need a record of what the human decided. I went looking for one properly. What I found, in a tenant with several hundred insider risk alerts:

**Most closed alerts carried no recorded reason for closure at all.** Not a bad reason. None.

**The only outcome field on the exported alert records was the generic incident enum from the detection platform**, and most of its values were the equivalent of "other". A category that fits attacks rather than employee conduct, applied to alerts about employee conduct.

**Hundreds of alerts had produced a grand total of two cases**, neither of which was ever concluded.

My first instinct was that somebody had been sloppy. That instinct was wrong, and the correction is the interesting part. [Microsoft's own guidance on managing alert volume](https://learn.microsoft.com/en-us/purview/insider-risk-management-best-practices-alert-tuning) recommends dismissing alerts in bulk, hundreds at a time, to keep the queue manageable. A bulk dismissal writes nothing down. **The absence of recorded decisions is not a failure of the process. It is what the documented process produces.**

Which means an accuracy figure is unavailable, not merely inconvenient. There is no answer key, and building one is not a data engineering problem.

I ran the pipeline against what labels did exist, purely to see. It "disagreed" with the recorded outcome on most of them. That number is meaningless and I am not going to repeat it, because it is measuring against a field that does not encode the judgment anybody cares about. **A precision figure computed from the wrong column is worse than no figure, because it survives being quoted.**

## Then you have to build the answer key

If the record of human judgment does not exist, the system has to create it as a by-product of being used.

Every verdict in the console now carries two buttons. Agree, or record a different verdict with a note. The response is written back against the incident and the exact procedure version that produced it, attributed to the signed-in reviewer, and it accumulates. Nobody is asked to do extra work. They are asked to press a key while reading something they were already reading.

Two design decisions in there matter more than the feature.

**Responses are keyed to the procedure version, not just the alert.** When somebody edits a procedure, every verdict it produced is legitimately open again, because the reasoning that a reviewer agreed with was generated by different text. Agreement does not carry forward through an edit. It should not.

**The author's own agreement is reported separately from everyone else's.** I wrote the procedures. Me agreeing with them measures my consistency, not the system's quality, and blending those two numbers into one flattering average is the kind of thing that gets found out at exactly the wrong moment. So the console keeps them apart, permanently, even though it makes the headline number smaller.

That second one costs nothing to implement and it is the difference between a measurement and a marketing figure.

## One thing the last post promised and this one can show

The argument for versioned procedures was always partly a promise: put the standard in a document, stamp the version onto the verdict, and you will be able to prove that changing the document changed the outcome.

I got to test that. Among the minority of alerts that did carry an analyst classification, several kept coming back benign that a reviewer had called malicious. The reason was a sentence I had written telling the model not to let one particular signal affect the verdict. The model had been following it correctly. So I changed the sentence, bumped the version, and redeployed.

**Fifteen verdicts moved.** Each one traceable to a specific procedure version, with the old answer still on file and the new one beside it. Nobody retrained anything and nobody touched a prompt. A person edited a document and the outcomes changed, provably.

That is the whole argument for keeping the standard outside the model, and it took two posts to get evidence for it.

## What the whole thing cost

I want to put a number on this because the objection I keep hearing about controls is that they are expensive.

Everything described in this post and the last one, running for a month, cost **$1.84**.

Not the model. Everything. Six workflows, the storage and query layer, the key store, the console, the ingestion for every record, every fixture run, every backtest, every re-judge, and every mistake I made along the way.

The model was $1.34 of that, across 840 assessments. **About a sixth of a cent per alert.** The other fifty cents is the entire rest of the architecture, which is to say the grounding check, the versioned procedures, the fixtures, the reviewer loop and the counters that caught the silent record loss all cost roughly nothing.

Two caveats, because a number nobody can reconstruct is exactly what I spent a section arguing against.

**That per-alert figure includes all the waste.** It is total spend divided by total assessments, and a large share of those assessments were me re-running things because something was broken. Steady-state marginal cost is lower than a sixth of a cent, not higher. I am quoting the pessimistic number because it is the one I can point at a bill for.

**It is pinned to this configuration.** A small model, a reasoning effort setting I have not changed, roughly 1,650 tokens in and 330 out per assessment because the payload is a bounded field list rather than a raw alert. Loosen any of those and the number moves. The architecture is what makes the payload small, so the cost and the privacy posture come from the same decision.

I am not going to extrapolate this to some enterprise volume, because I have not tested the throughput limits and a projected number would undo the point of a measured one. But at this scale the honest conclusion is that **nobody skips these controls because they are expensive. They skip them because they are work.**

## What actually changed my mind

I went into this expecting to catch a model inventing things. I built a fairly elaborate apparatus for exactly that.

In two days it produced no fabrications and nine flags, and **every one of the nine was in something I had built to watch, validate, or manage the model.** One of them was in the watching apparatus itself. Not one was in the judgment.

That pattern held everywhere once I started looking. The test harness produced four false failures before it produced a true one. A control that disabled a procedure had no way to re-enable it. A gate that required tests to pass stored its state in a file that got deleted constantly, so it fired on procedures that had passed an hour earlier.

Every one of those produced a **false alarm**, which is the more dangerous direction. A control that cries wolf gets bypassed, and then it is not a control, and everyone still thinks it is.

Meanwhile the model, given a clear procedure, a bounded field list, and a closed set of permitted answers, behaved.

I do not think that generalizes to every use of a language model, and I would not want anyone to read it as "the models are fine now". The setup matters enormously: it never sees free text it does not need, it cannot answer outside four values, and every claim it makes is checked. Constrain the problem hard enough and you get a well-behaved component.

But it does suggest the risk sits somewhere other than where most of the attention is. **The model is one component in a system, and the rest of the system is code somebody wrote in a hurry, under-tested, and trusted more than the model because it isn't AI.**

## The position

Three things I would now argue for in any system that lets a model make a call about a person.

**Make it cite its sources, and check them with code.** Prose reasoning that reads well and is quietly wrong is the most dangerous output one of these systems can produce, precisely because nothing about it looks wrong. Structured claims turn that from a matter of whether a reviewer was paying attention into a mechanical test.

**Instrument for silence.** Count what you found and what you judged, separately, and derive the difference rather than trusting a counter. Assume you will lose records. You will, and the failure will not announce itself.

**Do not claim an accuracy number you cannot show the working for.** If the ground truth does not exist in your environment, say that, and build the loop that creates it. "We built the measurement and it has three weeks of data in it" is a stronger position than a percentage nobody can reconstruct.

And one more, less comfortable than the others.

**Trust your scaffolding less than you trust your model.** The model gets scrutinized because it is new and strange. The hundred lines of query, validation, retry and packaging around it get scrutinized only once they break, which is considerably later than you would like.

The verifier I built to catch a model lying spent its first two days catching me. I would rather have found that out this way than in a room with somebody asking why an alert about their employee got closed.

## What's still open

Three things I have not solved, in case anyone wants to tell me I am wrong about them.

**No measured agreement yet.** The loop that captures reviewer responses exists and works, and it currently holds nothing. Until somebody other than me uses it, everything above is a claim about controls rather than about accuracy.

**The tier that judges people has no regression test.** Every procedure that judges a single alert is gated by fixtures with known answers. The one that builds a picture of a person across surfaces, which is the one making the strongest claim, is the one nothing verifies. I know exactly how that sentence sounds.

**Withheld fields are never scanned for manipulation.** The injection pre-check reads what the model reads. A procedure can name a field as attacker-writable and still keep it out of the prompt, and instruction text planted there is never recorded. The model is not at risk from text it never receives, so this is a gap in detection rather than in defense, but somebody trying to manipulate triage is worth knowing about even when the attempt was going to fail.

---

*Nothing here is a Microsoft position or a product roadmap. It is one build, in one lab tenant, with synthetic data, and every conclusion in it should be read against that. The pipeline, procedures, fixtures and console are mine.*
