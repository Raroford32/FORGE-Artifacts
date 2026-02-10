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
# Discovery Module — Value-Drain 0-Day Investigation Engine
#
# Each prompt below carries the investigation framework: the mission,
# the core principles, and the stage-specific reasoning guide.
# This creates a coherent reasoning thread across all stages —
# the same investigator, building understanding progressively.
#
# Import the framework so prompts stay in sync with the methodology.
# ──────────────────────────────────────────────────────────────
from discovery.framework import (
    MISSION,
    SYSTEM_IDENTITY,
    CORE_PRINCIPLES,
    STAGE_1_GUIDE,
    STAGE_2_GUIDE,
    STAGE_3_GUIDE,
    STAGE_4_GUIDE,
    DRAINAGE_MECHANICS,
    TRANSITION_1_TO_2,
    TRANSITION_2_TO_3,
    TRANSITION_3_TO_4,
    KNOWN_VULNS_GUIDE,
)


@ell.simple(model=MODEL, client=CLIENT, temperature=0.3)
def invoke_contract_decompose(source_code: str):
    """Phase 1 — Build a complete understanding of the contract's value system."""
    return [
        ell.system(SYSTEM_IDENTITY),
        ell.user(
            f"""MISSION: {MISSION}

You are beginning Phase 1 of a multi-phase investigation. Read the reasoning
framework below carefully — it will guide your thinking through this phase
and all subsequent phases.

{CORE_PRINCIPLES}

{STAGE_1_GUIDE}

Now read the source code below and build your value-lifecycle model.
Output as structured JSON wrapped in ```json``` blocks. Include every
observation, even those that do not fit neatly into a category — the goal
is completeness of understanding, not conformity to a template.

```solidity
{source_code}
```

Begin Phase 1 analysis."""
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.4)
def invoke_attack_surface_mapping(contract_profile: str):
    """Phase 2 — Find where value conservation breaks."""
    return [
        ell.system(SYSTEM_IDENTITY),
        ell.user(
            f"""MISSION: {MISSION}

{TRANSITION_1_TO_2}

You are now in Phase 2. Read the reasoning framework and the Phase 1 output
below, then conduct your adversarial analysis.

{CORE_PRINCIPLES}

{STAGE_2_GUIDE}

Below is the complete Phase 1 output — the value-lifecycle decomposition of
the contract under investigation. This is YOUR understanding from the
previous phase. Build on it.

{contract_profile}

Output drain surfaces as a JSON array wrapped in ```json``` blocks. For each
drain surface include: value_path, broken_invariant, manipulation_vector,
state_window, extraction_sequence, scale.

Begin Phase 2 analysis."""
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.5)
def invoke_hypothesis_generation(contract_profile: str, attack_surfaces: str, known_vulns_context: str):
    """Phase 3 — Construct concrete attack hypotheses."""
    return [
        ell.system(SYSTEM_IDENTITY),
        ell.user(
            f"""MISSION: {MISSION}

{TRANSITION_2_TO_3}

You are now in Phase 3. You have the value-lifecycle model (Phase 1) and the
drain surfaces (Phase 2). Your task is to construct complete attack hypotheses.

{CORE_PRINCIPLES}

{STAGE_3_GUIDE}

Additionally, here is context about how value has been drained from real-world
contracts — described as mechanics, not labels. Use this to build intuition,
not to pattern-match:

{known_vulns_context}

=== PHASE 1 OUTPUT (Value Lifecycle) ===
{contract_profile}

=== PHASE 2 OUTPUT (Drain Surfaces) ===
{attack_surfaces}

Output hypotheses as a JSON array wrapped in ```json``` blocks. Each hypothesis
must include: title, value_flow_break, attack_sequence, initial_state,
caller_requirements, net_extraction, why_it_works, amplification, verification_plan.

Begin Phase 3 analysis."""
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.4)
def invoke_discovery_prompt_synthesis(
    contract_profile: str,
    attack_surfaces: str,
    hypotheses: str,
    protocol_type: str,
):
    """Phase 4 — Synthesize self-contained investigation prompts."""
    return [
        ell.system(SYSTEM_IDENTITY),
        ell.user(
            f"""MISSION: {MISSION}

{TRANSITION_3_TO_4}

You are now in Phase 4 — the final phase. You have the complete investigation:
value lifecycle (Phase 1), drain surfaces (Phase 2), and attack hypotheses
(Phase 3). Transform everything into self-contained investigation prompts.

{STAGE_4_GUIDE}

=== PHASE 1 OUTPUT (Value Lifecycle) ===
{contract_profile}

=== PHASE 2 OUTPUT (Drain Surfaces) ===
{attack_surfaces}

=== PHASE 3 OUTPUT (Attack Hypotheses) ===
{hypotheses}

Output as JSON with two keys: "discovery_prompts" (array of prompt objects)
and "investigation_roadmap" (array of ordered investigation steps with
rationale). Wrap in ```json``` blocks.

Begin Phase 4 synthesis."""
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.3)
def invoke_known_vulns_synthesis(dataset_context: str, protocol_type: str):
    """Process historical vulnerability data into value-drainage mechanics."""
    return [
        ell.system(SYSTEM_IDENTITY),
        ell.user(
            f"""MISSION: {MISSION}

You are processing historical data to build a knowledge foundation for the
investigation. This is NOT a categorization exercise. You are extracting
the MECHANICS of value drainage — the physics of how money has actually
left smart contracts in the real world.

{KNOWN_VULNS_GUIDE}

Here is data from real-world audit reports. Process it according to the
framework above. Focus on findings relevant to: {protocol_type}

{dataset_context}

Output as structured plain text organized by drainage mechanic — not by
vulnerability label. Group cases where the same conservation break occurred
even if they have different traditional names."""
        ),
    ]
