# 21 — Contained Computer-Use & Workflow Automation

> **Status: forward-looking.** This is a **future product direction**, not built and not on the
> near-term backlog. It is documented to fix where the enclave goes as agents move from *reading*
> work data ([doc 19](19-ai-gateway.md)) to
> *operating* work apps. Its differentiated form depends on the same Endpoint Security entitlements
> that gate enforcement today ([doc 14](14-production-and-development-platform-requirements.md)).

The loop this describes: **record** how work gets done → distill it into an **SOP** → let a
**computer-use agent** run the same apps a person would. Clave's contribution is **not** the agent —
it is the **contained, audited environment** that makes agentic execution on real work apps safe
enough to trust.

The one-sentence version: **Clave is the managed environment an AI agent operates inside** —
contained filesystem, scoped screen/input, brokered egress, and a tamper-evident record of every
action — which is exactly what makes *"let an agent run your work apps"* not reckless.

---

## 1. Why this belongs in the enclave

An agent that *operates* apps is a process with initiative: it clicks, types, reads the screen, and
moves data — autonomously. That is the same thing the enclave already governs for a **human**, one
step more autonomous. The boundary does not care whether a human or a model is driving.

This is the through-line that unifies the AI work with the original product. The **tamper-evident
audit spool** ([doc 10 §6](10-policy-engine-and-ipc.md)) is one substrate under all of it, with three
subjects:

| Subject | What crosses the boundary | Governed by |
|---|---|---|
| A **human** | clipboard / files / screen | [doc 05](05-clipboard-dlp.md)–[07](07-screen-capture-protection.md) |
| A **machine egressing** | a prompt to a model | [doc 19](19-ai-gateway.md) |
| A **machine acting** | clicks, keystrokes, app actions | **this document** |

One boundary, one verified record, three subjects. Computer-use is the enclave's *acting-machine*
face, and it reuses the containment, the audit, and the egress broker the earlier docs already build.

---

## 2. The loop, and an honest difficulty gradient

Three stages, and they are **not** equally hard. Say so up front.

| Stage | What it is | Difficulty |
|---|---|---|
| **Record** | Capture how a task is actually done in work apps | **Solvable** — observation primitives + accessibility tree + the encrypted store already exist (§3) |
| **Distill → SOP** | Turn noisy capture into a correct, parameterized procedure | **Hard AI problem** — this is where process-mining lives; not a prompt (§4) |
| **Automate** | A computer-use agent replays the SOP driving the same apps | **Frontier / brittle** — 2026 computer-use agents misclick and fail on UI change (§5) |

The strategic consequence: **build behind the security wedge, and let design partners pull this.**
The AI-gateway docs ship first and stand alone; this loop is Act 2, and its riskiest stage
(automate) is the one the containment story most directly de-risks.

---

## 3. Record — scoped to the work zone

The record stage is [doc 18](18-activity-tracking-and-monitoring.md) taken from **metrics to
actions**. Doc 18 already ships a *"work-zone-only, tamper-evident"* usage stream where **the
supervised set is the sensor** — a personal app is never in `ZoneRegistry`, so it *physically cannot*
appear in a sample. Computer-use recording inherits that privacy line exactly: it records **only work
windows and work apps**, never the employee's personal screen.

It reuses primitives Clave already has:

- **Structured capture over pixels.** The OS accessibility tree (the same source doc 17's contained
  browser and the screen-capture watch in [doc 07](07-screen-capture-protection.md) touch) yields UI
  elements and actions, with OCR only as a fallback — cheaper and more replayable than screenshots.
- **The Clave Disk is the store.** Recordings are work data at rest, encrypted, crypto-shreddable —
  not a personal SQLite with cloud sync.
- **The audit spool is the ledger.** Each recorded action is a hash-chained event, tamper-evident and
  gateway-verifiable.

> **✗ The differentiated (work-scoped) recorder is ES-gated on macOS**, the same wall as the rest of
> enforcement ([doc 14](14-production-and-development-platform-requirements.md)). A recorder that
> captures *everything* is buildable now — but it throws away the boundary that is the entire point.
> The contrast to name: the consumer "screen memory" recorders now emerging capture to a **personal**
> store with optional cloud sync and **no company boundary, no contained execution, no egress control,
> no signed audit.** Clave's version is the enterprise-contained inverse — and those same unmanaged
> tools are exactly the exfiltration surface [doc 07](07-screen-capture-protection.md) /
> [doc 19](19-ai-gateway.md) exist to *detect*.

---

## 4. Distill → SOP — the company-owned artifact

Turning a raw capture into a **generalizable, parameterized** procedure ("refund a customer in
Stripe": find order → verify amount → issue refund → note the ticket) is the genuine AI value-add,
and the genuinely hard part — it is unsolved-in-general, and it is where every process-intelligence
company pours effort. This document does not pretend it is a prompt.

Two disciplines carry over regardless of how the distillation model improves:

- **Bring-your-own-model, brokered.** The distillation runs through the AI gateway
  ([doc 19](19-ai-gateway.md)) — the company's enterprise tenant, inspected and attributed. The
  recording of real work never egresses to a consumer endpoint.
- **The SOP is policy-shaped.** A distilled SOP is a company-owned, versioned, signed artifact carried
  like a `PolicyBundle` — authored/edited at the console, versioned, revocable. It is not a script on
  the employee's disk.

---

## 5. Automate — containment is what makes it safe

An agent driving real work apps (finance, CRM, internal tools) that misclicks can do real damage — a
wrong transfer, a deleted record. In 2026, computer-use agents are still **brittle** at multi-step
real-app driving. So the value Clave adds to this stage is not the agent; it is that **the environment
bounds the blast radius:**

| Containment property | Why it makes execution trustworthy |
|---|---|
| Contained filesystem (Clave-Disk work view) | The agent can only touch work data — [doc 17 §4.1](17-web-app-auth-and-browser-containment.md) |
| Scoped screen/input | The agent reads/acts on work windows only, never the personal desktop |
| Brokered + inspected egress | Anything it sends goes through [doc 19](19-ai-gateway.md) |
| Every action audited | A tamper-evident record of what the agent did, per SOP ([doc 10 §6](10-policy-engine-and-ipc.md)) |
| Reversible | Work state lives on a crypto-shreddable, snapshot-able volume ([doc 04](04-encrypted-volume.md)) |

**Bring-your-own-agent.** Clave is the *environment*, not the brain — the customer brings Claude
computer-use or their own agent, and Clave supplies the sandbox and the ledger. That keeps the product
on its actual competency (the boundary) instead of betting the company on building a frontier agent.

> **✗ Scoping what an agent may screen-read and gating input injection are ES-gated on macOS** — the
> hard version of this stage waits on the same entitlements as enforcement. State it plainly.

---

## 6. The de-risked entry: the contained browser

There is a buildable, **portable** slice of this whole loop that sidesteps the ES wall and runs on the
*most reliable* execution surface: the **contained browser** already defined in
[doc 17](17-web-app-auth-and-browser-containment.md).

- **DOM beats pixels.** Web-app automation acts on structured elements, where computer-use agents are
  far more reliable than on arbitrary desktop UI.
- **The container already exists.** `LaunchProfile::chromium()` / `ContainerKind::Chromium` already
  emits a contained `--user-data-dir` persona profile inside the Clave Disk, `classify_path` already
  places it in the work zone, and it is **not ES-gated** ([doc 17 §8](17-web-app-auth-and-browser-containment.md)
  Phase A is "Blocked on: —").
- **Record → SOP → replay, entirely inside that contained browser**, is the vertical slice that tests
  the vision without a multi-quarter bet on brittle desktop computer-use.

Start here if this direction is pursued at all.

---

## 7. Why this makes Clave more relevant

As work shifts from apps-humans-drive to agents-that-act, the question every company faces becomes
*"what can an agent see and do on this unmanaged machine, and can I prove it?"* That is the enclave's
question, one subject over. Clave's boundary is already the right **shape** for it; the alternatives
(consumer personal-capture recorders, uncontained RPA) have no boundary, no custody, no signed record.

Be honest about what that implies commercially: this is a **second product category** — AI-native RPA
/ process intelligence, sold to an operations buyer, not only the CISO the enclave sells to today. The
tech composes; the go-to-market is a second motion. So this is deliberately **Act 2**: ship the
AI-gateway wedge, prove *"governed AI on BYOD,"* and let those customers tell you whether they want the
record→automate loop before building it on spec.

---

## 8. Build order

Mostly gated — sequenced behind the AI-gateway wedge, and behind the same ES entitlements as
enforcement.

| Phase | Work | Delivers | Blocked on |
|---|---|---|---|
| **A** | Record → SOP → replay inside the **contained browser** (§6) | The vision, portable, on the reliable surface | — |
| **B** | SOP artifact model (versioned, signed, console-authored) carried like `PolicyBundle` (§4) | Company-owned, revocable procedures | Console authoring (NG-6) |
| **C** | Work-scoped **desktop** recording (§3) | Capture beyond the browser | **ES entitlement** ([doc 14](14-production-and-development-platform-requirements.md)) |
| **D** | Contained desktop **execution** — scoped screen/input, audited actions (§5) | Agents operate native work apps, contained | **ES entitlement**; distillation maturity |

Phase A is a real extension of doc 17's contained browser plus doc 19's gateway; everything past it
depends on either the entitlement wall or the maturity of computer-use itself. Build A, and let demand
decide the rest.
