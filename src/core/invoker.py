import os
import sys
import ell
import yaml
import dotenv
from loguru import logger
from openai import OpenAI

with open("config.yaml", "r") as f:
    CONFIG = yaml.safe_load(f)

VERBOSE = CONFIG["global"]["verbose"]
INTERVAL = CONFIG["global"]["interval"]
TIMEOUT = CONFIG["global"]["timeout"]
LOG_LEVEL = CONFIG["global"]["log_level"]
logger.remove()
logger.add(
    sink=sys.stdout,
    colorize=True,
    level=LOG_LEVEL,
)
LOG_DIR = CONFIG["global"]["log_dir"]
LOG_FILE = CONFIG["global"]["log_file"]
MAX_RETRIES = CONFIG["global"]["max_retries"]
dotenv.load_dotenv(CONFIG["global"]["env_path"])
API_KEY = os.getenv("API_KEY")
logger.debug(f"API_KEY: {API_KEY}")
MODEL = CONFIG["llm"]["model"]
BASE_URL = CONFIG["llm"].get("base_url", None)
TEMPERATURE = CONFIG["llm"]["parameters"]["temperature"]
CHUNK_LENGTH = CONFIG["extractor"]["chunk_length"]
CLIENT = OpenAI(
    api_key=API_KEY if API_KEY else "ollama",
    base_url=BASE_URL,
    timeout=TIMEOUT,
    max_retries=MAX_RETRIES,
)

os.environ["TIKTOKEN_CACHE_DIR"] = (
    os.getenv("TIKTOKEN_CACHE_DIR") or "extractor/__pycache__"
)
ell.init(verbose=VERBOSE, store=LOG_DIR, autocommit=False)
ell.config.register_model(
    MODEL, CLIENT, supports_streaming=CONFIG["llm"]["parameters"]["streaming"]
)


@ell.simple(model=MODEL, client=CLIENT, temperature=TEMPERATURE)
def invoke_map(document: str):
    return [
        ell.system("You are Axiom, an AI expert in smart contract security."),
        ell.user(
            'You are given a document containing excerpts from various sources such as smart contract audit reports or bug bounty disclosures. Your task is to extract relevant information if mentioned about the audited project and all security vulnerabilities involved. Specifically, find any links, addresses or references to where the project source code audited can be found(e.g., GitHub repository with certain commit id (branch id), on-chain address and chain name). Besides, identify and extract the following details:\nVulnerability Title, Vulnerability Description (answer "n/a" if not provided), Severity Level (answer "n/a" if not provided), Location of Vulnerability (contract, function, etc.). \nPlease format the output clearly. Start your response with "Answer: " followed by the extracted details. If no relevant information is found, reply with "Answer: None".'
        ),
        ell.user(
            "Assistant: Yes, I understand. I am Axiom, and I will extract all relevant vulnerabilities information from the document fragment you provided."
        ),
        ell.user(
            f"Document fragment:\n{document}\n\n---\n Please start extracting the information."
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=TEMPERATURE)
def invoke_reduce(map_results: str):
    output_example = """```json\n{"project_info": { "url": "https://github.com/xxx/xxx/", "commit_id": "ad048598b092457acf346orkhg9898987", "address": "n/a", "chain": "n/a" }, "findings": [ { "id": 0, "title": "Out of gas in includeInReward() function", "description": "The function `includeInReward()` uses a loop to...", "severity": "Low", "location": "includeInReward()" },...]}\n```"""
    return [
        ell.system("You are Axiom, an AI expert in smart contract security."),
        ell.user(
            'You are given a set of extracted vulnerability info from a smart contract audit report or bug bounty disclosure. These fragments include information about various vulnerabilities (potential duplicates or invalid entries may be present) and details related to the source code (such as GitHub repository links or on-chain addresses). Your task is to: \n1. Clean and deduplicate the extracted vulnerability data\n2. Organize the relevant source code details (e.g., GitHub URL, on-chain address, and chain name)\n3. Generate a well-structured JSON output in the following format: \n{ "project_info": { "url": "<GitHub repository URL, if exists>", "commit_id": "<branch or commit hash/name/id, if exists>", "address": "<On-chain address, if exists>", "chain": "<Blockchain name (e.g., eth, bsc, base, polygon), if exists>" }, "findings": [ {"id":0, "title": "<Vulnerability title>", "description": "<Detailed description of the vulnerability>", "severity": "<Severity level (e.g., Low, Medium, High, Critical)>", "location": "<The contract or funtion or line where the vulnerability code is located or affected component>"},{"id": 1,...},... ] }.\n\n Use a null value "n/a" for missing fields or entries that could not be determined.'
        ),
        ell.user(
            "Assistant: Yes, I understand. I am Axiom, and I will clean, deduplicate, and organize the extracted vulnerability data and source code details to generate a structured JSON output."
        ),
        ell.user(
            f"Extracted data:\n{map_results}\n\n\n Please Remember combine the fragments and output one well-structured JSON format like: {output_example}"
        ),
    ]


# @ell.simple(model=MODEL, client=CLIENT, extra_body={"options": {"num_ctx": 5120}})
@ell.simple(model=MODEL, client=CLIENT, temperature=TEMPERATURE)
def invoke_classify(cwe_info: str, vuln_info: str):
    return [
        ell.system(
            "You are Axiom, an AI expert in vulnerability analysis. Your task is to perform Root Cause Analysis on a given vulnerability title and description, and map the root cause to relevant Common Weakness Enumeration (CWE) ID from the list user provided. Remember, you're the best AI expert in vulnerability analysis and will use your expertise to provide the best possible analysis."
        ),
        ell.user(
            """I will provide a vulnerability's title and description, and you will perform Root Cause Analysis by mapping the root cause to relevant CWE ID from the list I provided. Here are some examples:\n\nExample 1:\nInput:\ntitle: Unimplemented Logic in distributePoolRewardsAdmin() Function\ndescription: The distributePoolRewardsAdmin() function has a comment indicating reward calculation logic, but the actual implementation is missing.\n\nOutput:\nAnswer: CWE-1068 - Inconsistency Between Implementation and Documented Design\n\nExample 2:\nInput:\ntitle: Crowdsale logic depends on Ethereum block timestamp\ndescription: The logic for determining the stage of the token sale and whether the sale has ended uses 'now', an alias for block.timestamp. This value can be manipulated by miners up to 900 seconds per block.\n\nOutput:\nAnswer: CWE-829 - Inclusion of Functionality from Untrusted Control Sphere\n\nExample 3:\nInput:\ntitle: Front-running fallback root update might lead to additional withdrawal\ndescription: A front-running attack might allow an attacker to withdraw a deposit one additional time if the system is not updated before the fallback withdrawal period is reached.\n\nOutput:\nAnswer: CWE-362 - Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')\n\nExample 4:\nInput:\ntitle: Transfer Function Failure with Fallback\ndescription: The transfer function may fail if msg.sender is the contract address with a fallback function, resulting in locked funds.\n\nOutput:\nAnswer: CWE-20 - Improper Input Validation\n\nNow, please prepare for a new vulnerability title and description provided."""
        ),
        ell.user(
            "Yes, I understand. I am Axiom, and I will analyze the provided vulnerability to map its root cause to relevant CWE ID from the list you provided."
        ),
        ell.user(
            f"{vuln_info}\n\n Candidate CWE list:\n{cwe_info}\n\nAnswer: Please think step-by-step briefly to reach the right conclusion. Output the CWE ID that best matches in the end like `Answer: CWE-284`."
        ),
    ]


# ──────────────────────────────────────────────────────────────
# Discovery Module — Value-Drain 0-Day Reasoning Engine
#
# Every prompt below is built on ONE axiom:
#   "A vulnerability exists iff an unprivileged caller can construct
#    a transaction sequence that ends with them holding more value
#    than they started with, at the expense of the protocol or its
#    users."
#
# There are no labels, no traditional categories, no checklists.
# The LLM is guided to reason from first principles about VALUE
# CONSERVATION — where it holds, and where it breaks.
# ──────────────────────────────────────────────────────────────


@ell.simple(model=MODEL, client=CLIENT, temperature=0.3)
def invoke_contract_decompose(source_code: str):
    """Map the complete value lifecycle of a smart contract."""
    return [
        ell.system(
            "You are a first-principles reasoner about value in EVM smart contracts. "
            "You do not think in vulnerability labels or audit checklists. "
            "You think in terms of value: where it enters, how it is tracked, "
            "what transforms it, what conditions release it, and where it exits. "
            "A contract is a state machine that moves value. Your job is to map "
            "that machine with absolute precision so every assumption about value "
            "conservation becomes explicit."
        ),
        ell.user(
            """Decompose the following smart contract purely in terms of its VALUE LIFECYCLE.

Produce a JSON document with these sections:

1. **value_entry_points**
   Every path through which value (ETH, tokens, NFTs, shares, reward credits — anything
   with economic worth) enters this contract. For each path list:
   - the function and its caller requirements
   - the token/asset type
   - how the incoming value is recorded in internal accounting
   - whether the recorded amount equals the actual amount received (or could diverge)

2. **value_exit_points**
   Every path through which value leaves this contract. Same detail as above, plus:
   - what conditions gate the release
   - who decides the amount
   - whether the amount is computed from internal accounting or actual balance

3. **internal_accounting**
   Every state variable or mapping that represents a claim on value (balances, shares,
   debt positions, reward accumulators, allowances, etc.). For each:
   - what value it tracks
   - which functions increase it, which decrease it
   - whether its sum across all holders is supposed to equal some actual balance

4. **value_transformations**
   Every place where value is converted, exchanged, minted, burned, split, or merged.
   For each transformation:
   - the mathematical formula used
   - whether rounding/truncation occurs and in whose favour
   - what external data (prices, rates, timestamps) feeds into the calculation
   - whether the transformation is atomic or can be interrupted mid-state

5. **value_gates**
   Every assumption, check, or condition that the code relies on to prevent unauthorized
   value extraction. For each gate:
   - the exact condition (code-level)
   - what makes it true under normal operation
   - what external or caller-controlled inputs could make it false
   - whether the gate can be evaluated at a moment when the state is inconsistent
     (e.g. during a callback, between two steps of a multi-step operation)

6. **external_value_dependencies**
   Every external contract call, oracle read, or off-chain data dependency that
   influences how value moves. For each:
   - what data is consumed and how it affects value calculations
   - what happens if the external source returns an unexpected value, reverts,
     or behaves differently from the code's implicit expectation
   - whether the caller can influence the external source's return value within
     the same transaction (or across a small number of blocks)

7. **value_conservation_invariants**
   State explicitly every equation or inequality that MUST hold for the protocol
   to be solvent — e.g. "sum of all user shares × pricePerShare ≤ contract token
   balance". List every invariant you can derive, even if it seems obvious.

Be exhaustive. Output as a single JSON object wrapped in ```json``` blocks.
Every missed value path is a potential drain vector.
"""
        ),
        ell.user(
            "Understood. I will map every atom of value flow with zero assumptions "
            "and zero reliance on named vulnerability patterns."
        ),
        ell.user(
            f"```solidity\n{source_code}\n```\n\nBegin value lifecycle decomposition."
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.4)
def invoke_attack_surface_mapping(contract_profile: str):
    """Identify every point where value conservation could break."""
    return [
        ell.system(
            "You are an adversarial reasoner. You are given a complete map of how "
            "value flows through a smart contract. Your sole objective: find every "
            "point where the conservation of value could be violated — where an "
            "unprivileged caller can end a transaction sequence holding more value "
            "than they started with. You do not use vulnerability labels. You reason "
            "from the value map itself."
        ),
        ell.user(
            f"""Below is a complete value-lifecycle decomposition of a smart contract.

Your task: enumerate every DRAIN SURFACE — a concrete mechanism by which an
unprivileged external caller could extract net positive value from this contract.

For each drain surface, provide:

**a) The value path**
   Which entry points, transformations, and exit points are involved?
   Trace the exact flow: caller puts in X of asset A, interacts with the contract,
   and extracts Y of asset B where value(Y) > value(X).

**b) The broken assumption**
   Which specific value gate or conservation invariant fails? Why?
   What must be true for the gate to hold, and how does the caller make it false?

**c) The manipulation vector**
   What does the caller control that lets them break the assumption?
   Consider: call ordering, intermediate callbacks, external contract behavior,
   flash-borrowed capital, block timing, price source influence, governance weight,
   contract deployment, or any combination thereof.

**d) The state window**
   Is there a moment during execution when internal accounting is inconsistent
   with actual balances? When the code has updated one variable but not yet
   another? When an external call is in flight and the caller gets control back?
   Describe the exact state window and what the caller can do inside it.

**e) The extraction sequence**
   Write the step-by-step transaction sequence (or multi-tx sequence) that
   the caller executes. Be concrete:
   - Tx 1: call X with parameters ...
   - During callback / in next block: call Y ...
   - Final state: caller gained Z tokens net

**f) Scale of extraction**
   Is this a single-shot drain, a repeated small leak, or an escalating
   feedback loop? What bounds the extraction (if anything)?

Think about the contract as a black box that transforms inputs to outputs.
The attacker's goal is simple: arrange inputs so outputs exceed inputs.
Do not label anything with traditional names. Describe the MECHANICS.

Output as a JSON array of drain surfaces, each with the fields above.
Wrap in ```json``` blocks.

Contract value decomposition:
{contract_profile}
"""
        ),
        ell.user(
            "I will systematically examine every value transition and find where "
            "conservation breaks. Pure mechanics, no labels."
        ),
        ell.user("Begin drain surface enumeration."),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.5)
def invoke_hypothesis_generation(contract_profile: str, attack_surfaces: str, known_vulns_context: str):
    """Construct concrete value-extraction sequences from first principles."""
    return [
        ell.system(
            "You are a constructive adversary. Given a value map and a list of "
            "potential drain surfaces for a smart contract, your job is to build "
            "CONCRETE attack hypotheses — specific transaction sequences where "
            "an unprivileged caller ends with more value than they started. "
            "You think from first principles about how value conservation can "
            "fail. You do not reference named vulnerability classes. You do not "
            "produce checklists. Every hypothesis is a specific, mechanistic "
            "story about value flowing from the protocol to the attacker."
        ),
        ell.user(
            f"""You have two inputs:

1. A value-lifecycle decomposition of a smart contract
2. A list of drain surfaces where value conservation may break

Additionally, here is context about how value has been drained from
similar contracts in the real world — described purely in terms of
mechanics, not labels:
{known_vulns_context}

Your task: for each drain surface (and for any NEW drain vector you
identify by combining surfaces), construct a COMPLETE ATTACK HYPOTHESIS.

Each hypothesis must answer ONE question:
  "How does an unprivileged caller end a transaction sequence holding
   more value than they started with?"

For each hypothesis provide:

1. **title**: A short description of the value-drain mechanic (not a
   vulnerability label — describe what happens to the value).

2. **value_flow_break**: Which specific conservation invariant breaks?
   Write the invariant as a mathematical statement and show how the
   attack violates it.

3. **attack_sequence**: Numbered steps. Each step is a concrete
   transaction or operation:
   - Who calls what function with what arguments
   - What state changes occur
   - What external calls fire and what happens during them
   - What value moves where at each step

4. **initial_state**: What must be true before the attack starts?
   (e.g. contract holds ≥N tokens, a certain pool exists, etc.)

5. **caller_requirements**: What does the attacker need?
   (only: capital, deployed contracts, timing — NOT privileges)

6. **net_extraction**: What does the attacker gain and what does the
   protocol/users lose? Be specific about amounts in terms of the
   contract's variables.

7. **why_it_works**: A plain-English explanation of WHY the code fails
   to prevent this. What did the developers assume that is actually
   false? What state transition did they not foresee?

8. **amplification**: Can this be repeated? Does each iteration
   amplify the next? What bounds the total extraction?

9. **verification_plan**: Concrete steps to confirm or refute this
   hypothesis:
   - Specific Foundry/Hardhat test to write
   - Exact values to use in the test
   - What assertion proves the drain

Generate at least 10 hypotheses, ordered by net extraction magnitude.
Every hypothesis must be mechanistically complete — someone reading it
should be able to write the exploit code directly.

Output as a JSON array wrapped in ```json``` blocks.

Contract value decomposition:
{contract_profile}

Drain surfaces:
{attack_surfaces}
"""
        ),
        ell.user(
            "I will construct complete, mechanistic attack sequences — each one "
            "a precise story of value leaving the protocol and entering the "
            "attacker's wallet."
        ),
        ell.user("Begin hypothesis construction."),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.4)
def invoke_discovery_prompt_synthesis(
    contract_profile: str,
    attack_surfaces: str,
    hypotheses: str,
    protocol_type: str,
):
    """Synthesize self-contained investigation prompts from the complete analysis."""
    return [
        ell.system(
            "You are a precision instrument builder. Your job is to take a complete "
            "value-drain analysis of a smart contract and distill it into a set of "
            "self-contained investigation prompts. Each prompt will be handed to an "
            "analyst (human or LLM) who has never seen this contract. The prompt must "
            "contain everything they need to investigate one specific value-drainage "
            "opportunity — the relevant code, the exact question, the verification "
            "steps. No labels, no generic checklists. Every prompt is about one "
            "concrete question: can value be drained through THIS specific mechanism?"
        ),
        ell.user(
            f"""You are given:
- A value-lifecycle decomposition
- A list of drain surfaces
- A set of attack hypotheses

Transform this analysis into SELF-CONTAINED INVESTIGATION PROMPTS.

Each prompt targets ONE value-drainage opportunity and must include:

1. **id**: Unique numeric identifier.

2. **title**: What value-flow is under investigation (describe the mechanic,
   not a vulnerability label).

3. **system_context**: A system prompt that sets up the investigator's
   mindset. Always frame it as: "You are investigating whether [specific
   value-flow mechanic] allows an unprivileged caller to extract net
   positive value."

4. **analysis_prompt**: The full investigation prompt. This must contain:
   - The relevant source code snippets (inline, not referenced)
   - The specific value-conservation invariant being tested
   - The hypothesized break mechanic
   - Concrete questions to answer (can X happen? what if Y?)
   - Numerical examples to check
   - Edge cases to consider

5. **focus_areas**: 2-4 specific things to look at (described as value-flow
   mechanics, not vulnerability names).

6. **contract_context**: The exact code snippets relevant to this
   investigation (extracted from the analysis).

7. **investigation_guide**: Step-by-step instructions to verify:
   - What test to write (Foundry/Hardhat)
   - What initial state to set up
   - What transaction sequence to execute
   - What assertion proves/disproves the drain
   - How to measure the net value extraction

Also produce an **investigation_roadmap** — an ordered list of which
prompts to investigate first (by expected severity of drain) and how
findings from one investigation feed into the next.

The prompts must work STANDALONE. An analyst receiving one prompt has
everything needed to conduct a complete investigation of that specific
value-drainage vector.

Output as JSON with two keys:
  "discovery_prompts": [array of prompt objects]
  "investigation_roadmap": [array of ordered steps with rationale]

Wrap in ```json``` blocks.

Value decomposition:
{contract_profile}

Drain surfaces:
{attack_surfaces}

Attack hypotheses:
{hypotheses}
"""
        ),
        ell.user(
            "I will produce precision investigation instruments — each one a "
            "complete, self-contained probe into a specific value-drainage path."
        ),
        ell.user("Begin prompt synthesis."),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.3)
def invoke_known_vulns_synthesis(dataset_context: str, protocol_type: str):
    """Extract value-drainage mechanics from historical findings."""
    return [
        ell.system(
            "You are a historian of value drainage in smart contracts. You study "
            "past exploits and audit findings NOT to build checklists, but to "
            "understand the fundamental MECHANICS of how value conservation was "
            "broken. You describe each case purely in terms of what value moved "
            "where and why the code failed to prevent it. No vulnerability labels. "
            "No categories. Just mechanics."
        ),
        ell.user(
            f"""Below is data from real-world audit reports and exploits.

Extract the VALUE-DRAINAGE MECHANICS — not a list of vulnerability types,
but a set of mechanical descriptions of how value left the protocol and
entered an attacker's control.

For each mechanic you identify, describe:

1. **What value moved**: tokens, ETH, shares, debt, collateral — what
   specific economic value was extracted?

2. **How the code's model diverged from reality**: Every drain happens
   because the code believes something that is not true. What was the
   false belief? (e.g. "the code believed the balance had not changed
   since the last checkpoint" or "the code assumed the price feed
   reflected the true market price at the time of settlement")

3. **What the attacker controlled**: What input, timing, or external
   state did the attacker manipulate to make the false belief exploitable?

4. **The extraction sequence**: In mechanical terms, what happened?
   (e.g. "Caller deposited, triggered a callback during which they
   withdrew, then the original deposit completed against a stale
   balance record")

5. **Why the gate failed**: What check or condition was supposed to
   prevent this, and why did it not work?

Organize by MECHANIC, not by label. Group cases where the same
fundamental conservation break occurred even if they have different
traditional names.

This output will be used to reason about NEW mechanics that have NOT
been seen before. The goal is to build intuition about HOW value
conservation breaks, so we can predict where it will break next.

Dataset context:
{dataset_context}

Target protocol context: {protocol_type}

Output as structured plain text organized by drainage mechanic.
"""
        ),
        ell.user(
            "I will extract the mechanics of value drainage — the physics of "
            "how money escapes smart contracts — not a taxonomy of labels."
        ),
        ell.user("Begin mechanical analysis."),
    ]
