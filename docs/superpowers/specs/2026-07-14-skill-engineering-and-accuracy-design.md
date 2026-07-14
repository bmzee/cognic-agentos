# Skill Engineering & Accuracy — the discipline

**Status:** DRAFT for maintainer review
**Date:** 2026-07-14
**Scope:** durable doctrine, not a milestone artifact. Consumed first by M8.5-D (sprint D-S6), then by **every bank onboarding thereafter**.

---

## 1. Why this document exists

> **The kernel governs. The skill *knows*. Accuracy is the product.**

Governance makes the system **deployable**. Accuracy makes it **worth deploying**. A bank that cannot trust the number will not use the system, no matter how beautifully it refuses unauthorized queries.

And relational data is unforgiving in a way prose is not:

> **You cannot hallucinate on relational data. A wrong number is worse than a refusal, because it is *believed*.**

A chatbot that waffles is annoying. An analytical agent that reports **£4.2m** when the answer is **£3.8m** — because it double-counted across a fan-out join — is a *liability*, and nothing on the screen will tell anyone it was wrong.

**Everything that determines whether the answer is right lives in the skill.** The model is a constant; the governance is a constant; the schema is given. The skill is the only variable we control, and it is therefore the only place accuracy can come from.

### 1.1 This is also the business

The kernel is the same for every bank. **The skills are not** — every bank has its own schema, its own vocabulary ("NPL", "CASA", "float"), its own traps. So:

**Skill engineering is the onboarding motion.** Point it at a bank's warehouse, author the skills, run the corpus, publish the number, iterate until it clears the bar, *then* go live. That is a repeatable, chargeable, defensible process — and the corpus is the artifact that lets a bank's own data team **verify us rather than trust us**.

---

## 2. What a skill actually is

A skill is a `SKILL.md` instruction package (ADR-025) — no code, no LLM inside it. It is read by the agent through the gated `read_skill` built-in **after** the assignment gate passes. It is the agent's entire knowledge of a schema.

**A skill that only lists tables and columns is not a skill. It is a schema dump, and it will produce wrong answers.** The anatomy of one that works:

| Part | Why it exists |
|---|---|
| **Schema map** | Tables, columns, types — the floor, not the ceiling. |
| **Grain declaration** | *"One row in `SALES` is one line item of one order on one day."* **The single largest source of wrong numbers is a model that misunderstands what one row means.** |
| **Join paths — explicit** | Not "these tables are related." *"`SALES.cust_id` → `CUSTOMERS.cust_id`; never join `SALES` to `PROMOTIONS` directly — go through `TIMES`."* Wrong join path is error #1. |
| **Traps, named** | The fan-out double-count. The `NULL`-in-`NOT IN` trap. The time hierarchy that has *both* `calendar_month` and `fiscal_month`. Name them, or the model will find them. |
| **Business vocabulary → columns** | *"'Churn' means `cust_valid = 'I'`."* The bank's words are not the schema's words, and the gap is where hallucination lives. |
| **Query patterns** | Year-over-year. Rolling windows. Top-N per group. The idioms this schema demands, written out. |
| **Worked examples** | Question → the correct SQL → why. The single highest-leverage content in the file. |
| **When to REFUSE** | *"If the question does not specify a period, ask — do not assume the current year."* **A skill that never teaches refusal will teach guessing.** |

### 2.1 The context constraint

Skill bodies are read into the model's context. They compete with the schema, the conversation, and the question itself. **A 40-page skill is not a better skill — it is an unread one.** Structure for progressive disclosure: description (always visible) → body (read on demand) → deep-reference sections the body points to only when needed.

---

## 3. Ground truth — the problem everyone gets wrong

To measure accuracy you need to know the right answer to thousands of questions. **You do not get it by hand-writing thousands of answers.** That is unaffordable, and it rots the moment the data changes.

### The mechanism

> **A human who knows the schema writes the *reference SQL*. The system executes it. The result **is** the ground truth.**

```
question:      "What were total sales by product category in Q3 2001?"
reference_sql: SELECT p.prod_category, SUM(s.amount_sold) ...   ← authored by a human who knows the schema
expected:      <executed at eval time>                          ← never hand-typed
```

This is tractable (writing correct SQL is far cheaper than computing correct answers), it **self-updates** when the data changes, and it is **auditable** — a bank's own DBA can read the reference SQL and tell you whether *your ground truth* is right. That last property matters enormously: it converts "trust our benchmark" into "check our benchmark."

### The scoring rule

> **Score the RESULT, never the SQL string.**

There are many correct spellings of one correct query and exactly one correct answer. Comparing SQL text rewards mimicry and punishes valid alternatives — it measures conformity, not correctness.

- Result-set equality: **order-insensitive** unless the question implies an order (then compare ordered).
- Numeric tolerance for floats; exact for counts and money.
- Column-name-insensitive, value-sensitive.

### Refusal is a CORRECT outcome — and must be scored as one

**This is the rule most benchmarks get wrong, and it is the one that matters most to a bank.**

The corpus contains questions that are **ambiguous**, **unanswerable from the schema**, or **outside the user's entitlement**. For those, the correct behaviour is to **say so**. A system that refuses when it does not know is *strictly better* than one that guesses plausibly.

Four outcomes, four scores:

| Outcome | Verdict |
|---|---|
| Answerable → correct answer | ✅ |
| Answerable → wrong answer | ❌ **the worst outcome** |
| Answerable → refused | ⚠️ a miss, but a **safe** one — track separately |
| Unanswerable/ambiguous → refused | ✅ |
| Unanswerable/ambiguous → answered anyway | ❌ **hallucination — count and publish it** |

**Report the wrong-answer rate and the hallucination rate as first-class numbers, never folded into one "accuracy" figure.** A single blended percentage hides exactly the failure a bank fears.

---

## 4. Scale — thousands of queries, and where they come from

Four sources, in ascending order of value:

**1. The golden set (hand-authored, small, precious).** A few dozen per schema, written by whoever authored the skill. Every one has reference SQL. This is the seed.

**2. Variations (generated, human-reviewed — this is where the thousands come from).** Each golden question is paraphrased **N** ways, all mapping to the **same** reference SQL:

> *"Total sales by category in Q3 2001"* · *"how much did each product category sell July–September 2001"* · *"q3 01 revenue split by category"* · *"show me the category-wise sales for the third quarter of 2001"*

Vary **phrasing, formality, abbreviation, jargon, typos, and under-specification**. This is not padding — **phrasing sensitivity is exactly where NL→SQL breaks**, and one golden question × 20 variations is a far better test than 20 unrelated questions. Generated by a model, **reviewed by a human** (a paraphrase that changes the meaning silently poisons the corpus — this review is not optional).

**3. Adversarial cases (hand-designed, mandatory).** A corpus of easy questions measures nothing. Every schema's corpus must include:
- the **fan-out double-count** (join that multiplies rows before an aggregate)
- the **wrong grain** (asking at a level the fact table does not support)
- the **time-hierarchy trap** (calendar vs fiscal; week-of-year boundaries)
- the **ambiguous column** (two tables, same column name, different meaning)
- the **plausible-but-wrong filter** (a status code that *looks* like the one you want)
- the **unanswerable question** (correct outcome: refuse)
- the **entitlement probe** (correct outcome: refuse — and this is a *governance* test riding the same corpus)

**4. Replay (post-demo, post-pilot — the highest-value source of all).** Real questions from real users. ADR-010 already ships a **replay** lane. Every live question becomes a candidate corpus entry; every live failure becomes a regression case. **This is the flywheel: the system gets more accurate the more it is used, and the evidence is durable.**

---

## 5. The improvement loop — what "skill building" actually is

Accuracy is not authored. **It is iterated toward, with a number in front of you.**

```
   author skill ──► run corpus ──► CLUSTER the failures ──► fix the SKILL ──► re-run
        ▲                                                                       │
        └───────────────────────────────────────────────────────────────────────┘
                        every fixed case stays in the corpus forever
```

**Clustering is the step that turns a score into an action.** A run that reports "73%" is useless. A run that reports *"31 of 47 failures are the same wrong join path"* tells you exactly which paragraph to write. Cluster by root cause:

| Failure cluster | The skill fix |
|---|---|
| Wrong join path | Write the join path explicitly. Name the forbidden shortcut. |
| Wrong grain / double-count | Declare the grain. Add a worked fan-out example showing the correct pattern. |
| Missed or wrong filter | Map the business term to the column and value. |
| Hallucinated column | Tighten the schema map; add "columns that do NOT exist but users ask for." |
| Answered an ambiguous question | Add the refusal rule. |
| Correct SQL, wrong presentation | Fix the output contract, not the skill. |

**The corpus is a regression suite.** A case that was fixed and later re-breaks is a **regression**, and it fails the gate — exactly the discipline the kernel already runs under. **The skill and its corpus are ONE signed artifact**: change the skill, re-run its evidence, or it does not ship.

---

## 6. Tooling — most of it already exists

**Already built (ADR-010):** `evaluation/` ships `corpus.py`, `runner.py`, `scorers.py`, `judge.py` (LLM-as-judge), `replay.py`, `adversarial/`, plus portal routes at `/api/v1/eval/bulk-run` and a CLI (`agentos eval bulk`).

**What must be added (small, and it is the sprint D-S6 delta):**

1. A **result-equivalence scorer** for SQL answers (order-aware, numeric-tolerant) — the existing scorers are text/judge-oriented.
2. A **reference-SQL corpus format** — question · reference SQL · scope · expected-outcome (`answer` | `refuse`) · tags.
3. **Failure clustering** in the report — by root cause, not by test id. *This is the difference between a score and a to-do list.*
4. A **variation generator** (model-generated paraphrases + a human review gate).
5. **Corpus-in-pack**: the skill pack carries its own corpus, signed with it.

**LLM-as-judge is deliberately NOT the primary scorer here.** For "did the number come out right", exact result comparison is *objective and free*; a judge is slower, costlier, and can be wrong. Reserve the judge for the parts that genuinely need judgement — was the *refusal* well-explained, was the *presentation* faithful to the data.

---

## 7. Cost, cadence, and honesty

- **Thousands of questions × a real model call is real money.** Run the full corpus at a **release gate**, not on every commit; run the affected schema's corpus on any change to that skill. The eval runner already supports parallelism.
- **Test the model you ship.** A cheaper model in the harness measures a system nobody will run.
- **Publish the number with its failures.** *"91% on 2,400 questions across six schemas; the 9% breaks down as: 4% refusals on ambiguous questions (safe), 3% wrong join on the promotions dimension (fix in flight), 2% wrong answers (listed below)."*
  **A bank told "100%" stops believing you. A bank shown its own failure modes — and shown that the system refuses rather than guesses — starts trusting you.** That is the entire game.

---

## 8. The bar (proposed — maintainer to rule)

Before a skill ships to a bank:

- **Wrong-answer rate < 2%** on the full corpus (this is the number that matters; a wrong number is a liability).
- **Hallucination rate = 0%** on unanswerable questions — *it must never invent an answer it cannot ground*. This is a hard gate, not a target.
- **Every adversarial case passes**, or its failure is documented and accepted in writing.
- **Refusal rate on answerable questions is reported**, not gated — refusing too much is a usability problem, not a safety one, and we would rather ship it than ship a guesser.

**Open for ruling:** are those the right thresholds, and is *hallucination = 0* the right hard gate? My recommendation is yes — **it is the only number a bank's risk committee will actually care about**, and it is the one claim we can make that no competitor pointing an LLM at a database can match.
