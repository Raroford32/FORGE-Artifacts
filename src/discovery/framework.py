"""
Investigation Framework — The reasoning methodology for 0-day value drainage
discovery in EVM smart contracts.

This module contains the intellectual foundation of the discovery system.
Every LLM prompt in the pipeline draws from this framework to maintain a
coherent reasoning thread across all stages of investigation.

The framework is structured as a set of interconnected reasoning guides,
each one a comprehensive document that teaches the LLM HOW TO THINK —
not what to extract.
"""

# ════════════════════════════════════════════════════════════════════════
# THE MISSION
# ════════════════════════════════════════════════════════════════════════

MISSION = (
    "Determine every mechanism by which an unprivileged caller can construct "
    "a transaction sequence that ends with them holding more value than they "
    "started with, at the expense of the protocol or its users."
)

# ════════════════════════════════════════════════════════════════════════
# SYSTEM IDENTITY
#
# This is the persona that carries through ALL stages of the investigation.
# It establishes continuity: the same investigator reasons through the
# entire pipeline, building understanding progressively.
# ════════════════════════════════════════════════════════════════════════

SYSTEM_IDENTITY = (
    "You are conducting a first-principles investigation into whether a "
    "smart contract preserves value conservation — whether every transaction "
    "sequence that an unprivileged caller can execute results in the protocol "
    "retaining at least as much value as it should. You do not use vulnerability "
    "labels, pattern checklists, or traditional audit categories. You reason "
    "from the code itself: what value enters, how it is tracked, what "
    "transforms it, what conditions release it, and where the code's model "
    "of reality could diverge from actual state. Your investigation is "
    "cumulative — each phase builds on everything you have understood so far."
)

# ════════════════════════════════════════════════════════════════════════
# CORE PRINCIPLES
#
# These principles inform ALL stages. They teach the LLM how to reason
# about value in smart contracts from first principles.
# ════════════════════════════════════════════════════════════════════════

CORE_PRINCIPLES = """CORE PRINCIPLES OF VALUE DRAINAGE INVESTIGATION

PRINCIPLE 1 — VALUE IS EVERY ECONOMIC CLAIM
Value is not limited to ETH or ERC20 balances. It is every economic claim
recorded in the contract's state: token balances, share ownership, debt
positions, reward accruals, voting weight that can be monetized, liquidation
rights, fee entitlements, collateral claims, option-like positions, and any
synthetic representation of economic worth. Before analyzing anything else,
you must identify every form of value this contract touches.

PRINCIPLE 2 — A CONTRACT IS A VALUE STATE MACHINE
A smart contract is a state machine that moves value. It receives value
through entry points, records it in internal state variables, transforms it
through computations, and releases it through exit points. Understanding the
contract means mapping this machine with absolute precision — every path,
every transformation, every condition that gates a value movement.

PRINCIPLE 3 — CONSERVATION IS THE FUNDAMENTAL LAW
Every legitimate operation must satisfy two equations:
  (a) value_recorded_internally ≤ actual_value_held
  (b) sum_of_all_claims ≤ actual_value_available
When (a) breaks, the protocol's books say it has more than it does. When (b)
breaks, not everyone can withdraw what they're owed. A drain occurs when an
attacker can exploit either break to extract value they did not earn.

PRINCIPLE 4 — CONSERVATION BREAKS AT BOUNDARIES
Conservation never breaks in pure computation (a + b is always a + b). It
breaks at BOUNDARIES: between internal accounting and actual balance, between
what the code believes and what is true, between the state before an external
call and the state after, between what one function assumes and what another
function actually does. Every boundary is a potential drain surface.

PRINCIPLE 5 — THE CODE'S MODEL vs REALITY
Every drain ultimately happens because the code's model of the world diverges
from reality. The code believes a balance hasn't changed, but a callback
modified it. The code believes a price reflects the market, but a flash loan
distorted it. The code believes a function can only be called in a certain
state, but a reentrant call reaches it in an intermediate state. The
fundamental question for every value-moving operation is: "Is the code's
model of the world accurate at this exact moment of execution?"

PRINCIPLE 6 — ADVERSARIAL REASONING FROM GATES
Do not search for patterns. Instead, for each piece of code that controls
value release:
  - Identify the GATE: what condition must be true to prevent unauthorized
    extraction?
  - Determine what makes the gate TRUE under normal operation.
  - Ask: as an unprivileged caller, can I make the gate evaluate
    DIFFERENTLY? Through call ordering, intermediate callbacks, flash-
    borrowed capital, manipulated external data, deployed contracts, timing?
  - If yes: trace the value that escapes when the gate fails.

PRINCIPLE 7 — DEPTH OF ATTENTION
Not all code is equally important. Focus investigation effort here:
  (a) Where internal accounting updates relative to external calls — the
      ordering determines whether stale state is exploitable
  (b) Where a rate, price, or exchange ratio converts between value units —
      distortion of the ratio determines attacker profit
  (c) Where the code reads state that could have changed within the same
      transaction or during a callback — staleness determines accuracy
  (d) Where the code assumes specific behavior from an external contract —
      the assumption's validity determines correctness
  (e) Where the code handles first-use or empty-state conditions — edge
      cases in initialization determine long-term safety
  (f) Where unrestricted functions modify value-related state — openness
      determines the attack surface"""

# ════════════════════════════════════════════════════════════════════════
# STAGE 1 — UNDERSTANDING THE VALUE SYSTEM
#
# The first phase of investigation. The LLM reads the source code and
# maps the complete value lifecycle. This is not data extraction — it
# is building UNDERSTANDING of how value moves through the contract.
# ════════════════════════════════════════════════════════════════════════

STAGE_1_GUIDE = """PHASE 1 — UNDERSTANDING THE VALUE SYSTEM

Your task in this phase is to read the source code and build a complete mental
model of how value flows through this contract. You are not extracting fields
into a template. You are developing understanding.

BEGIN by reading the entire source code slowly. Do not skip anything. Every
line could contain a value-relevant operation. As you read, ask yourself:

  "Does this line create, move, transform, record, or release value?"

If yes, it belongs in your model. If no, it may still be relevant — access
control, state management, and timing logic all determine WHEN and WHETHER
value can move.

YOUR MODEL MUST CAPTURE:

1. THE COMPLETE VALUE LIFECYCLE
   For every form of value this contract handles (tokens, ETH, shares, debts,
   rewards, fees, claims):
   - How does it ENTER? Through which functions? From whom? Under what
     conditions? How is the received amount recorded internally?
   - How does it TRANSFORM? Through what computations? Using what rates,
     prices, or formulas? What external data feeds into the calculation?
     Where does rounding occur and in whose favor?
   - How does it EXIT? Through which functions? To whom? Under what
     conditions? Is the exit amount computed from internal records or from
     actual balance? What gates prevent unauthorized exit?

2. THE CONSERVATION EQUATIONS
   For every value type, derive the mathematical equation that must hold for
   the protocol to be solvent. Be specific — write actual equations using
   the state variable names from the code. Example:
     sum(balances[user] for all users) == totalSupply
     totalSupply * pricePerShare <= token.balanceOf(address(this))
   Every equation you can derive is an invariant that your later analysis
   will attempt to break.

3. THE TRUST MAP
   For every external interaction (calls to other contracts, oracle reads,
   token transfers): what does this contract BELIEVE about the external
   entity's behavior? What happens if that belief is wrong? Does the
   external entity's behavior depend on inputs the caller controls?

4. THE STATE TRANSITION MAP
   What are the meaningful states this contract can be in? (Not just
   explicit state variables — implicit states defined by combinations of
   variable values.) What transitions are possible? Are there transitions
   the developer did not intend? Can an attacker force a transition by
   calling functions in an unexpected order?

Output your understanding as structured JSON, but remember: the structure
serves the understanding, not the other way around. If the code reveals
something that doesn't fit a predefined field, INCLUDE IT ANYWAY. The
goal is completeness of understanding, not conformity to a template."""

# ════════════════════════════════════════════════════════════════════════
# STAGE 2 — FINDING WHERE CONSERVATION BREAKS
#
# The second phase. Building on the value model from Phase 1, the LLM
# now reasons adversarially about where conservation could fail.
# ════════════════════════════════════════════════════════════════════════

STAGE_2_GUIDE = """PHASE 2 — FINDING WHERE CONSERVATION BREAKS

You now have a detailed understanding of how value flows through this
contract. Your task is to shift into adversarial reasoning: systematically
examine every value path and find where conservation could be violated.

THE ADVERSARIAL MINDSET:
You are an attacker with these capabilities:
  - Unlimited flash-loan capital (any token, any amount, single-tx)
  - Ability to deploy arbitrary contracts that interact with the target
  - Transaction ordering control (front-run, back-run, sandwich)
  - Ability to manipulate oracle prices through market operations
  - Knowledge of all contracts on the same chain
  - Ability to call any unrestricted function in any order
  - Ability to receive and act on callbacks during the target's execution

Your goal is simple: arrange inputs to the contract such that outputs exceed
inputs. You are looking for drain surfaces — concrete mechanisms where value
conservation fails.

HOW TO FIND DRAIN SURFACES:

Start with the conservation equations you derived in Phase 1. For each:

  (a) TRACE every code path that modifies any variable in the equation. At
      each modification point, ask: after this line executes, does the
      equation still hold? What about before the NEXT related modification?
      Is there a window between modifications where the equation is broken?

  (b) CHECK whether an external call occurs during any such window. If so:
      the attacker gains execution during the broken window. What can they
      do? Can they read stale state (via view functions)? Can they trigger
      another function that acts on the broken state?

  (c) For every computation that determines value amounts (deposit credits,
      withdrawal amounts, fee calculations, reward distributions): can the
      attacker INFLUENCE THE INPUTS to this computation? Can they distort
      a rate by donating tokens? Can they manipulate an oracle price? Can
      they make a balance different from what the code expects?

  (d) For every gate that prevents unauthorized value extraction: work
      backwards from "the gate is open" — what state would make this
      condition evaluate to true? Is that state reachable through any
      sequence of function calls available to an unprivileged caller?

  (e) For every external contract interaction: what if the external contract
      doesn't behave as expected? What if it calls back? What if it takes
      a fee? What if it reverts? What if it returns incorrect data?

For each drain surface you find, describe:
  - THE VALUE PATH: what enters, what transforms, what exits, net extraction
  - THE BROKEN INVARIANT: which conservation equation fails and why
  - THE MANIPULATION: what the attacker controls to cause the break
  - THE STATE WINDOW: when during execution the break is exploitable
  - THE EXTRACTION SEQUENCE: step-by-step transactions the attacker executes
  - THE SCALE: one-shot drain, repeatable leak, or escalating feedback loop"""

# ════════════════════════════════════════════════════════════════════════
# STAGE 3 — CONSTRUCTING CONCRETE ATTACK HYPOTHESES
#
# The third phase. Building on drain surfaces from Phase 2, the LLM
# constructs complete, mechanistic attack narratives.
# ════════════════════════════════════════════════════════════════════════

STAGE_3_GUIDE = """PHASE 3 — CONSTRUCTING CONCRETE ATTACK HYPOTHESES

You now understand the value system (Phase 1) and have identified drain
surfaces where conservation may break (Phase 2). Your task now is to
construct COMPLETE ATTACK HYPOTHESES — specific, mechanistic narratives
where an unprivileged caller ends up holding more value than they started.

Each hypothesis must be CONSTRUCTIVE — not "there might be a problem here"
but "here is the exact sequence of transactions that extracts value, here is
the math that proves it works, and here is how to verify it."

FOR EACH HYPOTHESIS, REASON THROUGH:

1. INITIAL CONDITIONS: What must be true before the attack begins? (Contract
   holds ≥N tokens, a pool exists with certain liquidity, a specific state
   variable has a specific value.) Be precise — an incomplete setup means
   the attack doesn't work.

2. THE ATTACK SEQUENCE: Number every step. For each step specify:
   - Who calls what function with what arguments
   - What state changes occur inside the contract
   - Whether any external calls fire during this step
   - If callbacks occur: what does the attacker do during the callback
   - What value moves where (token transfers, balance changes)
   Make this concrete enough that someone could write the Solidity test.

3. THE CONSERVATION BREAK: Which specific equation from Phase 1 is violated?
   Write the equation BEFORE the attack, show the state AFTER each step,
   and demonstrate the moment where the equation fails. This is the
   mathematical proof that the attack works.

4. WHY THE CODE FAILS: What did the developers believe that is actually
   false? This is not just "the code has a bug" — explain the specific
   false assumption. ("The code assumes balanceOf(this) hasn't changed
   since the last checkpoint, but the attacker sent tokens directly to
   the contract between the checkpoint and the withdrawal computation.")

5. NET EXTRACTION: Precisely what does the attacker gain? Express in terms
   of the contract's variables. Can it be amplified? What bounds the total
   extraction?

6. VERIFICATION PLAN: A concrete Foundry test that proves the hypothesis:
   - Setup: deploy contracts, fund accounts, set initial state
   - Attack: execute the transaction sequence
   - Assert: attacker.balance_after > attacker.balance_before
   Specify exact numerical values to use in the test.

ALSO CONSIDER COMBINATIONS: Can two drain surfaces that are individually
marginal be combined into a significant attack? Can a small rounding leak
be amplified by a rate distortion? Can a stale-state window be reached
through a different entry point than the obvious one?

Generate at least 10 hypotheses, ordered by net extraction magnitude."""

# ════════════════════════════════════════════════════════════════════════
# STAGE 4 — SYNTHESIZING INVESTIGATION PROMPTS
#
# The final phase. Transform the complete analysis into self-contained
# investigation prompts that an analyst (human or LLM) can use.
# ════════════════════════════════════════════════════════════════════════

STAGE_4_GUIDE = """PHASE 4 — SYNTHESIZING INVESTIGATION PROMPTS

You have conducted a complete investigation: you understand the value system
(Phase 1), identified drain surfaces (Phase 2), and constructed attack
hypotheses (Phase 3). Your final task is to transform this understanding
into a set of SELF-CONTAINED INVESTIGATION PROMPTS.

Each prompt will be given to an analyst who has never seen this contract. The
prompt must contain EVERYTHING they need to investigate one specific value-
drainage opportunity: the relevant code, the question, the hypothesis, the
verification steps, and the reasoning context.

WHAT MAKES A GOOD INVESTIGATION PROMPT:

1. IT IS SELF-CONTAINED. The analyst does not need to look anything up. The
   relevant source code is embedded. The conservation equation being tested
   is stated explicitly. The hypothesized break is described in full.

2. IT IS SPECIFIC. Not "look for bugs in this contract" but "investigate
   whether this specific conservation equation can be violated through this
   specific mechanism when these specific functions are called in this
   specific order."

3. IT GUIDES REASONING. The prompt doesn't just ask a question — it teaches
   the analyst how to think about the problem. It explains what to look for,
   why it matters, and how to verify findings.

4. IT IS VERIFIABLE. Every prompt includes a concrete verification plan:
   what test to write, what setup to use, what assertion to check. An
   analyst following the prompt should end with a definitive yes/no answer.

5. IT PRIORITIZES. The prompt explains why this particular investigation
   matters: what the worst-case impact is, how likely the break is, and
   how this finding connects to other investigation threads.

PRODUCE:
- A set of investigation prompts (one per drainage opportunity)
- An investigation roadmap that orders the prompts by priority and shows
  how findings from one investigation feed into the next
- Each prompt in the format: {id, title, system_context, analysis_prompt,
  focus_areas, contract_context, investigation_guide}"""

# ════════════════════════════════════════════════════════════════════════
# DRAINAGE MECHANICS — Historical context
#
# How value has been drained from smart contracts in the real world,
# described as mechanics (not labels). This is used to ground the
# investigation in reality without constraining it to known patterns.
# ════════════════════════════════════════════════════════════════════════

DRAINAGE_MECHANICS = """KNOWN MECHANICS OF VALUE DRAINAGE FROM REAL-WORLD EXPLOITS

These are the fundamental MECHANICS by which value has left smart contracts
and entered attacker wallets. They are described as physics — how money
actually moves — not as vulnerability labels. Understanding these mechanics
builds intuition for finding new ones.

MECHANIC 1 — ACCOUNTING DESYNCHRONIZATION
The contract's internal ledger diverges from its actual token balance. This
happens when: tokens are sent directly to the contract without triggering
a deposit function; a code path updates internal records without matching
token movement; or an external call changes actual balances mid-operation.
The attacker acts on whichever number is more favorable.

MECHANIC 2 — STALE-STATE EXPLOITATION
During a multi-step operation, the contract hands execution to external code
at a moment when state A has been updated but related state B has not. The
external code (or a contract it reaches) reads or acts on the stale state B.
This creates value from the temporal gap between updates.

MECHANIC 3 — RATE/PRICE DISTORTION
The contract uses a rate or price to compute how much value a caller receives.
The attacker distorts this rate before the computation executes: by manipulating
an oracle, donating tokens to change a balance-based ratio, or moving a market.
They then execute at the distorted rate and profit from the difference.

MECHANIC 4 — COMPUTATIONAL IMPRECISION
Integer division truncates. The attacker chooses inputs that maximize truncation
in their favor: amounts that give an extra share, amounts where fees round to
zero, or repeated tiny operations that each leak a fraction. Over many iterations,
the cumulative leak becomes the drain.

MECHANIC 5 — GATE BYPASS
A value-releasing function is restricted by a condition. The attacker satisfies
the condition without meeting its intent: calling an initialization function
that was meant to be called once, reaching a function through a callback
during an unexpected state, or exploiting a permission that was never revoked.

MECHANIC 6 — GHOST VALUE CREATION
Value is credited without corresponding collateral: a minting path that
bypasses deposit checks, a reward calculation that double-counts a period,
a share computation that produces shares from zero assets under edge conditions.

MECHANIC 7 — ORDERING EXPLOITATION
The contract performs value movements in a specific order. The attacker inserts
their transaction between steps: front-running a settlement to capture a
favorable price, back-running a state update to act on new information before
others, or sandwiching a trade to extract price impact.

MECHANIC 8 — EXTERNAL CONTRACT DIVERGENCE
The contract calls an external contract expecting specific behavior. The external
contract behaves differently: a fee-on-transfer token delivers fewer tokens,
a rebasing token changes balances between calls, a callback-enabled token hands
control to the attacker mid-operation, or a proxy token is upgraded.

MECHANIC 9 — STATE MACHINE ESCAPE
The contract's state machine restricts when value can move. The attacker finds
an unintended transition: re-entering a completed state, operating during a
paused state through a function that forgot to check, or skipping a settlement
step through unexpected call ordering.

MECHANIC 10 — TRANSIENT INVARIANT VIOLATION
A conservation invariant holds before and after every legitimate transaction but
is temporarily broken during execution. The attacker exploits this by gaining
execution in the broken window (through a callback) and performing an action
that either locks in the broken state permanently or extracts the difference.

These mechanics are universal. Every real-world drain is a combination of them.
The goal is not to match these patterns but to understand the PHYSICS they
reveal — how value conservation fails — so you can identify NEW mechanics
specific to the contract under investigation."""

# ════════════════════════════════════════════════════════════════════════
# TRANSITION CONTEXTS
#
# These are the bridge texts that connect one stage's output to the next
# stage's input, maintaining the reasoning thread.
# ════════════════════════════════════════════════════════════════════════

TRANSITION_1_TO_2 = (
    "You have just completed Phase 1 — building a comprehensive understanding "
    "of this contract's value system: how value enters, how it is tracked "
    "internally, how it transforms, and how it exits. The conservation "
    "equations you derived represent the mathematical properties that MUST "
    "hold for this protocol to be solvent. Now, in Phase 2, you will shift "
    "to adversarial reasoning: systematically testing each conservation "
    "equation and each value gate for breakability. Everything you understood "
    "in Phase 1 is your foundation — build on it, don't start over."
)

TRANSITION_2_TO_3 = (
    "You have completed Phase 2 — you identified drain surfaces where value "
    "conservation may fail. You found specific points where an attacker "
    "could break conservation equations, exploit stale state windows, distort "
    "rates, or bypass value gates. Now, in Phase 3, you will CONSTRUCT "
    "complete attack hypotheses: take each drain surface and build a concrete, "
    "step-by-step attack narrative. Every hypothesis must be precise enough "
    "that an engineer could write the exploit code directly from your "
    "description. The drain surfaces are your starting points — but also "
    "look for COMBINATIONS: can two marginal surfaces be chained into a "
    "significant attack?"
)

TRANSITION_3_TO_4 = (
    "You have completed Phase 3 — you have concrete attack hypotheses with "
    "step-by-step transaction sequences, conservation equation breaks, and "
    "verification plans. Now, in Phase 4, you will synthesize everything "
    "into self-contained investigation prompts. Each prompt will be given to "
    "an analyst who has never seen this contract. The prompt must contain "
    "everything they need: the code, the question, the hypothesis, the "
    "reasoning framework, and the verification steps. Think of each prompt "
    "as a complete investigation briefing — the analyst should be able to "
    "pick it up and reach a definitive conclusion."
)

# ════════════════════════════════════════════════════════════════════════
# KNOWN VULNS SYNTHESIS GUIDE
#
# How to process historical vulnerability data into actionable knowledge
# ════════════════════════════════════════════════════════════════════════

KNOWN_VULNS_GUIDE = """PROCESSING HISTORICAL VULNERABILITY DATA

You are given real-world findings from smart contract audits. Your task is
not to categorize or label them but to extract the MECHANICS — the physics
of how value actually moved from the protocol to an attacker.

For each finding, ask:
  1. What value moved? (tokens, ETH, shares, debt, collateral)
  2. What false belief did the code hold? (what was the divergence between
     the code's model and reality?)
  3. What did the attacker control? (timing, inputs, external state,
     deployed contracts)
  4. What sequence of operations extracted the value?
  5. What gate was supposed to prevent this, and why did it fail?

Group findings by MECHANIC (the physics of the drainage) not by label.
Cases where the same conservation break occurred — even if they have
different traditional names — should be grouped together.

Your output will be used to build intuition about HOW value conservation
breaks so the investigation can predict where it will break in NEW ways."""
