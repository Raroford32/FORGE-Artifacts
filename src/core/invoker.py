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
# Adaptive Investigation Engine — Philosophy-Based Discovery
#
# The engine uses 5 focused invocations in an adaptive loop:
#   understand → generate → evaluate → refine → (loop) → guidebook
#
# Each invocation carries the framework philosophy and grounding
# rules. There is no fixed pipeline — the engine decides what to
# investigate based on what it discovers.
# ──────────────────────────────────────────────────────────────
from discovery.framework import (
    MISSION,
    SYSTEM_IDENTITY,
    PHILOSOPHY,
    AXIOMS,
    REASONING_METHOD,
    GROUNDING_RULES,
    EVALUATION_CRITERIA,
    ADAPTIVE_DEPTH,
    GUIDEBOOK_STANDARD,
    DATASET_EVIDENCE_GUIDE,
)


@ell.simple(model=MODEL, client=CLIENT, temperature=0.3)
def invoke_understand(source_code: str, dataset_context: str, prior_gaps: str = ""):
    """
    Adaptive understanding — reads source code and builds a complete
    model of value, trust, and state. If prior_gaps is provided (from
    a refinement iteration), focuses on addressing those specific gaps.
    """
    gap_instruction = ""
    if prior_gaps:
        gap_instruction = (
            f"\n\nIMPORTANT — PRIOR EVALUATION FOUND THESE GAPS:\n{prior_gaps}\n"
            "Your understanding MUST address these gaps specifically. "
            "Do not repeat previous analysis — focus on what was missed."
        )

    return [
        ell.system(SYSTEM_IDENTITY),
        ell.user(
            f"""MISSION: {MISSION}

{PHILOSOPHY}

{AXIOMS}

{REASONING_METHOD}

{GROUNDING_RULES}
{gap_instruction}

=== SOURCE CODE ===
```solidity
{source_code}
```

=== DATASET EVIDENCE (real-world findings from {len(dataset_context)} chars of audit data) ===
{dataset_context[:6000] if dataset_context else "No dataset evidence available."}

Read the source code above. Apply the reasoning method. Build your
understanding of:
1. Every form of value this contract touches
2. The complete lifecycle of each value type (entry → transform → exit)
3. The conservation equations (using actual variable names from the code)
4. Every boundary where the code's model meets reality
5. Every false belief the code might hold at each boundary

Output your understanding as structured analysis. Be exhaustive — cite
specific functions, variables, and code paths for every observation.
Do NOT invent content. Every statement must be traceable to the code above."""
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.5)
def invoke_generate_methodology(understanding: str, source_code: str, dataset_context: str):
    """
    Generate investigation methodology — prompts and guides that an
    analyst can follow to discover vulnerabilities in this specific contract.
    """
    return [
        ell.system(SYSTEM_IDENTITY),
        ell.user(
            f"""MISSION: {MISSION}

{GROUNDING_RULES}

{GUIDEBOOK_STANDARD}

You have completed a deep understanding of this contract (below). Now
produce INVESTIGATION METHODOLOGY — self-contained prompts and reasoning
guides that teach an analyst how to find every vulnerability this contract
might have.

=== YOUR UNDERSTANDING OF THE CONTRACT ===
{understanding}

=== SOURCE CODE (ground truth — verify all claims against this) ===
```solidity
{source_code[:8000]}
```

=== DATASET EVIDENCE (how similar code has failed in the real world) ===
{dataset_context[:4000] if dataset_context else "No dataset evidence."}

PRODUCE a JSON object with two keys, wrapped in ```json``` blocks:

{{
  "investigation_prompts": [
    {{
      "id": <int>,
      "title": "<specific investigation title>",
      "false_belief": "<what the code believes that might not be true>",
      "code_reference": "<specific function/variable/line cited>",
      "boundary_type": "<which boundary from the philosophy>",
      "investigation_steps": ["<step 1>", "<step 2>", ...],
      "verification_plan": {{
        "test_description": "<what Foundry test to write>",
        "setup": "<contract deployment and initial state>",
        "attack_sequence": "<exact function calls with arguments>",
        "assertion": "<what to check: attacker.balance_after > before>"
      }},
      "impact_if_confirmed": "<what happens to value if this belief is false>",
      "reasoning": "<WHY this investigation matters — the deep logic>"
    }},
    ...
  ],
  "reasoning_guides": [
    {{
      "title": "<guide title>",
      "scope": "<what part of the contract this covers>",
      "philosophy_connection": "<which axioms and boundaries apply>",
      "guide_content": "<detailed reasoning guide for this investigation area>",
      "key_questions": ["<question 1>", "<question 2>", ...]
    }},
    ...
  ]
}}

Requirements:
- Every prompt must cite specific code (function name, variable, line)
- Every prompt must include a verification plan
- Every prompt must explain WHY the investigation matters
- Prompts must be ordered by impact potential (highest first)
- Do NOT include prompts for patterns the code does not exhibit
- Cover EVERY value-moving function, external call, and arithmetic operation"""
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.2)
def invoke_evaluate(methodology: str, source_code: str, dataset_context: str):
    """
    Self-evaluation — strictly judge the quality of investigation methodology.
    Returns structured evaluation with quality score and specific gaps.
    """
    return [
        ell.system(
            "You are a strict, honest evaluator of investigation methodology. "
            "Your job is to find GAPS — things the methodology missed, claims "
            "that are not grounded in code, prompts that an analyst could not "
            "follow to a conclusion. You are NOT trying to validate the "
            "methodology — you are trying to BREAK it. Be harsh. A methodology "
            "that passes your evaluation must actually work."
        ),
        ell.user(
            f"""{EVALUATION_CRITERIA}

{GROUNDING_RULES}

You are evaluating investigation methodology produced for a smart contract.
Your evaluation must be STRICT. Check every criterion.

=== METHODOLOGY BEING EVALUATED ===
{methodology}

=== SOURCE CODE (check all code citations against this) ===
```solidity
{source_code[:8000]}
```

=== DATASET CONTEXT (verify evidence usage) ===
{dataset_context[:2000] if dataset_context else "No dataset evidence was available."}

EVALUATE by producing a JSON object wrapped in ```json``` blocks:

{{
  "quality_score": <float 0.0-1.0>,
  "criterion_scores": {{
    "value_path_coverage": <float>,
    "boundary_coverage": <float>,
    "grounding_quality": <float>,
    "actionability": <float>,
    "reasoning_depth": <float>
  }},
  "coverage_gaps": [
    "<specific function/variable/path that was NOT investigated>"
  ],
  "depth_issues": [
    "<specific prompt that needs deeper reasoning and WHY>"
  ],
  "grounding_failures": [
    "<specific claim that does not cite code or cites wrong code>"
  ],
  "strengths": [
    "<what the methodology does well>"
  ],
  "recommendation": "<'converge' if score >= threshold, else 'refine'>",
  "refinement_targets": [
    "<exact description of what to improve, with code references>"
  ]
}}

Be specific. "Needs more coverage" is useless feedback. "The swap()
function on line 45 was not investigated despite having an external
call to router.getAmountOut()" is useful feedback."""
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.4)
def invoke_refine(methodology: str, evaluation_feedback: str, source_code: str):
    """
    Refine methodology based on evaluation feedback. Addresses specific
    gaps without losing what already works.
    """
    return [
        ell.system(SYSTEM_IDENTITY),
        ell.user(
            f"""MISSION: {MISSION}

{GROUNDING_RULES}

You produced investigation methodology for a smart contract. An evaluator
found specific gaps and weaknesses. Your task is to REFINE the methodology
to address every gap while preserving everything that already works.

=== EVALUATION FEEDBACK ===
{evaluation_feedback}

=== CURRENT METHODOLOGY (preserve what works, fix what's broken) ===
{methodology}

=== SOURCE CODE (ground truth for all refinements) ===
```solidity
{source_code[:8000]}
```

PRODUCE the COMPLETE refined methodology as a JSON object wrapped in
```json``` blocks, with the same structure as the original:
  "investigation_prompts": [...],
  "reasoning_guides": [...]

RULES FOR REFINEMENT:
- Address EVERY gap listed in the evaluation
- Do NOT remove prompts that the evaluator praised
- New prompts must cite specific code (function, variable, line)
- New prompts must include verification plans
- If a grounding failure was identified, fix the citation or remove the claim
- The refined methodology must be STRICTLY BETTER than the original"""
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.3)
def invoke_synthesize_guidebook(
    methodology: str,
    understanding: str,
    evaluation_history: str,
    source_code: str,
):
    """
    Final synthesis — produce the self-validated investigation guidebook.
    This is the final output of the engine.
    """
    return [
        ell.system(SYSTEM_IDENTITY),
        ell.user(
            f"""MISSION: {MISSION}

{GUIDEBOOK_STANDARD}

You have produced investigation methodology through an iterative process
of generation, evaluation, and refinement. Now synthesize the FINAL
INVESTIGATION GUIDEBOOK — the definitive methodology for discovering
vulnerabilities in this contract.

=== FINAL METHODOLOGY (after all refinement iterations) ===
{methodology}

=== CONTRACT UNDERSTANDING (your deep analysis) ===
{understanding}

=== EVALUATION HISTORY (proof of self-validation) ===
{evaluation_history}

=== SOURCE CODE ===
```solidity
{source_code[:6000]}
```

PRODUCE the final guidebook as a JSON object wrapped in ```json``` blocks:

{{
  "guidebook_title": "<descriptive title for this investigation>",
  "protocol_summary": "<what this contract does, in one paragraph>",
  "investigation_prompts": [
    ... (the refined, validated prompts — ordered by priority)
  ],
  "reasoning_guides": [
    ... (the reasoning guides — organized by investigation area)
  ],
  "investigation_roadmap": [
    "<ordered list of investigation steps with rationale>"
  ],
  "key_findings_summary": "<what the methodology is most likely to uncover>",
  "methodology_confidence": "<assessment of how thorough this guidebook is>"
}}

This guidebook will be given to analysts who have never seen this contract.
It must be SELF-CONTAINED — everything they need to investigate is here.
Every prompt must cite specific code. Every guide must teach reasoning."""
        ),
    ]
