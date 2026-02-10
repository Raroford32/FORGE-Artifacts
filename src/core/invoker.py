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
# Discovery Module Invocations - 0-Day Vulnerability Hunting
# ──────────────────────────────────────────────────────────────


@ell.simple(model=MODEL, client=CLIENT, temperature=0.3)
def invoke_contract_decompose(source_code: str):
    """Deep structural decomposition of a smart contract."""
    return [
        ell.system(
            "You are Axiom, an elite smart contract security researcher with deep expertise in EVM internals, Solidity compiler behavior, DeFi protocol design, and novel attack vector discovery. You have discovered multiple 0-day vulnerabilities in production protocols. Your analysis goes far beyond automated tools - you reason about emergent behaviors, cross-function state corruption, economic invariant violations, and protocol-level design flaws that no scanner can detect."
        ),
        ell.user(
            """Perform an exhaustive structural decomposition of the following smart contract source code. You must extract EVERY detail with surgical precision - missing anything could mean missing a critical 0-day.

Extract and organize the following:

1. **CONTRACT IDENTITY**:
   - Contract name, compiler pragma (exact version constraints and their implications)
   - Inheritance chain (full linearization order and its security implications)
   - All imports and their trust implications
   - Whether this is a proxy, implementation, or standalone contract
   - Upgradeability pattern used (if any) and its specific variant

2. **STATE ARCHITECTURE**:
   - Every state variable: name, type, visibility, storage slot position implications
   - Mapping structures and their key spaces (what controls access to what data)
   - Nested mappings and structs (storage layout collision potential)
   - Immutable vs mutable state boundaries
   - State variables that represent balances, allowances, permissions, or protocol parameters

3. **FUNCTION SURFACE**:
   - Every function: name, visibility, modifiers, parameters, return values
   - Which state variables each function reads and writes (state mutation map)
   - All external calls made by each function (call graph to untrusted code)
   - Which functions are payable and handle ETH/native token
   - Which functions use assembly/inline Yul
   - Which functions use delegatecall, staticcall, or low-level call
   - Callback patterns (reentrancy surface)

4. **ACCESS CONTROL TOPOLOGY**:
   - All modifiers and their exact logic
   - Role hierarchy and privilege levels
   - Which addresses are trusted and how trust is established
   - Initialization/constructor trust assumptions
   - Owner/admin/guardian/timelock patterns

5. **VALUE FLOW MAP**:
   - All paths where tokens/ETH enter the contract
   - All paths where tokens/ETH leave the contract
   - Internal accounting vs actual balances
   - Fee calculation and distribution paths
   - Reward/yield calculation mechanisms

6. **EXTERNAL DEPENDENCY MAP**:
   - All external contract interfaces called
   - Oracle dependencies and how prices/data are consumed
   - Token standards interacted with (ERC20, ERC721, ERC1155, etc.)
   - DEX/AMM integrations
   - Governance/timelock dependencies

7. **DANGEROUS PATTERNS INVENTORY**:
   - Uses of assembly/Yul (exact operations)
   - Uses of delegatecall (target resolution logic)
   - Uses of selfdestruct/create/create2
   - Unchecked arithmetic blocks
   - Type casting operations
   - abi.encode vs abi.encodePacked usage (collision potential)
   - Block timestamp/number dependencies
   - tx.origin usage
   - Inline assembly memory operations

8. **PROTOCOL TYPE CLASSIFICATION**:
   - Classify the protocol type (lending, DEX/AMM, yield aggregator, bridge, staking, governance, NFT marketplace, etc.)
   - Identify the core protocol invariants that MUST hold
   - Identify the economic model and its assumptions

Format your response as structured JSON. Be exhaustive. Every missed detail is a potentially missed vulnerability.
"""
        ),
        ell.user(
            "Yes, I understand. I will perform the most thorough structural decomposition possible, treating every detail as potentially security-critical."
        ),
        ell.user(
            f"Smart Contract Source Code:\n```solidity\n{source_code}\n```\n\nBegin exhaustive decomposition. Output as structured JSON wrapped in ```json``` blocks."
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.4)
def invoke_attack_surface_mapping(contract_profile: str):
    """Map all attack surfaces from the structural decomposition."""
    return [
        ell.system(
            "You are Axiom, an elite offensive smart contract security researcher. You think like an attacker with unlimited resources, deep EVM knowledge, and access to flash loans, MEV infrastructure, and cross-protocol composability. Your specialty is finding attack surfaces that automated tools miss entirely - the kind that lead to real-world exploits worth millions."
        ),
        ell.user(
            """Given the following structural decomposition of a smart contract, perform an exhaustive attack surface analysis. Think beyond known vulnerability patterns. Consider how an attacker with the following capabilities would approach this contract:

**ATTACKER CAPABILITIES TO ASSUME**:
- Unlimited flash loan capital (any token, any amount)
- Ability to deploy arbitrary contracts that interact with this one
- MEV capability (transaction ordering, sandwich attacks, frontrunning)
- Ability to manipulate oracle prices through market operations
- Control over one or more governance token positions
- Knowledge of all deployed contracts on the same chain
- Ability to exploit timing between blocks and transactions
- Access to historical transaction data and state changes

**ATTACK SURFACE CATEGORIES TO ANALYZE**:

1. **ENTRY POINT ANALYSIS**:
   - Every external/public function is a potential entry point
   - For each: what can an unprivileged caller achieve?
   - What state transitions can be triggered and in what sequence?
   - What are the minimum requirements to call each function?

2. **CROSS-FUNCTION STATE CORRUPTION**:
   - Can calling function A in a specific state, then function B, produce an inconsistent state?
   - Are there multi-step operations that can be interrupted?
   - Can partial execution of one path corrupt assumptions of another?

3. **REENTRANCY SURFACE** (beyond simple reentrancy):
   - Read-only reentrancy (viewing stale state during callback)
   - Cross-contract reentrancy (through intermediary contracts)
   - Cross-function reentrancy (reenter different function during callback)
   - State inconsistency windows during external calls

4. **ECONOMIC/MATHEMATICAL ATTACK SURFACE**:
   - Precision loss accumulation paths
   - Rounding direction exploitation (round up on deposit, round down on withdrawal)
   - Share/exchange rate manipulation (first depositor, donation attacks)
   - Fee calculation bypass or manipulation
   - Inflation/deflation attack vectors
   - Price manipulation through flash loans

5. **ACCESS CONTROL SURFACE**:
   - Privilege escalation paths (can unprivileged user gain privileges?)
   - Missing authorization checks (functions that should be restricted but aren't)
   - Initialization front-running (can initialization be front-run or re-initialized?)
   - Governance capture scenarios
   - Timelock bypass possibilities

6. **ORACLE/EXTERNAL DATA SURFACE**:
   - Oracle manipulation impact paths
   - Stale price exploitation
   - TWAP manipulation feasibility
   - Multi-oracle inconsistency
   - Chainlink/price feed edge cases (sequencer downtime, L2-specific)

7. **TOKEN INTERACTION SURFACE**:
   - Fee-on-transfer token handling
   - Rebasing token handling
   - ERC777 callback exploitation
   - Approval race conditions
   - Permit/signature replay
   - Token contract upgrade risk (proxied tokens)

8. **STORAGE/MEMORY SURFACE**:
   - Storage collision in proxy patterns
   - Uninitialized storage/memory
   - Dirty memory from assembly
   - Transient storage (EIP-1153) edge cases

9. **PROTOCOL COMPOSABILITY SURFACE**:
   - How does this contract interact with the broader DeFi ecosystem?
   - Can positions in this protocol be used as collateral elsewhere?
   - Can flash loan attacks combine this with other protocols?
   - Liquidation cascade scenarios

10. **UPGRADE/MIGRATION SURFACE**:
    - Storage layout change risks
    - Function selector collision risks
    - Initialization gap during upgrade
    - Delegatecall context confusion

For each attack surface identified, provide:
- The specific entry point(s) involved
- The attack narrative (step-by-step how an attacker would exploit it)
- Preconditions needed
- Estimated impact (fund loss, protocol disruption, etc.)
- Why this would be missed by automated tools

Format output as structured JSON with an array of attack surfaces.
"""
        ),
        ell.user(
            "Understood. I will map every attack surface with offensive precision, thinking like a real-world attacker, going far beyond what any automated scanner would find."
        ),
        ell.user(
            f"Contract Structural Decomposition:\n{contract_profile}\n\nBegin attack surface mapping. Output as JSON in ```json``` blocks."
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.5)
def invoke_hypothesis_generation(contract_profile: str, attack_surfaces: str, known_vulns_context: str):
    """Generate novel vulnerability hypotheses that go beyond known patterns."""
    return [
        ell.system(
            "You are Axiom, the world's foremost 0-day vulnerability researcher for EVM smart contracts. You have a unique ability: you can reason about emergent vulnerabilities - bugs that arise not from individual code patterns but from the interaction of multiple correct-seeming components. You find the vulnerabilities that every auditor, every tool, and every formal verifier misses. Your hypotheses have led to the discovery of critical vulnerabilities in major DeFi protocols. You think in terms of invariant violations, not pattern matching."
        ),
        ell.user(
            f"""Given the contract decomposition and attack surface mapping below, generate NOVEL vulnerability hypotheses. These must go BEYOND known vulnerability patterns. Do NOT simply list reentrancy, overflow, access control - those are entry-level. Instead, reason about:

**HYPOTHESIS GENERATION FRAMEWORK**:

1. **INVARIANT VIOLATION REASONING**:
   - What mathematical invariants MUST hold for this protocol to be secure?
   - What state invariants MUST hold between function calls?
   - What economic invariants MUST hold for the tokenomics to be sound?
   - For each invariant: construct a sequence of transactions that could violate it
   - Consider: can an invariant be temporarily violated during a transaction and exploited before restoration?

2. **EMERGENT BEHAVIOR ANALYSIS**:
   - What happens when multiple independent features interact?
   - Are there state machine transitions that were not intended by the developers?
   - Can legitimate features be combined in an unintended way?
   - What emergent behaviors arise from the interaction with external contracts?

3. **ASSUMPTION GRAPH ATTACK**:
   - List every implicit assumption the code makes
   - For each assumption: under what conditions could it be violated?
   - Which assumptions depend on external state that an attacker controls?
   - Which assumptions are true today but could become false through protocol changes?

4. **TEMPORAL ATTACK VECTORS**:
   - Multi-block attack sequences (setup in block N, exploit in block N+1)
   - Time-dependent state drift (what changes between calls?)
   - Epoch/period boundary exploitation
   - Deadline/expiry edge cases

5. **COMPOSABILITY EXPLOIT CHAINS**:
   - Flash loan → price manipulation → this contract → profit extraction
   - Cross-protocol position manipulation
   - Governance attack chains (accumulate votes → malicious proposal → extraction)
   - Liquidation cascade triggers through this contract

6. **EVM-LEVEL EXPLOITATION**:
   - Gas-dependent behavior exploitation
   - Return data handling edge cases
   - ABI encoding edge cases with dynamic types
   - Selector collision exploitation
   - EVM precompile interaction edge cases

7. **UPGRADE/PROXY EXPLOITATION** (if applicable):
   - Can a malicious upgrade be crafted that appears benign?
   - Storage slot overlap between implementation versions
   - Initialization race conditions post-upgrade
   - Function selector collision between proxy and implementation

8. **NOVEL CROSS-CUTTING CONCERNS**:
   - What if this contract is called as part of a larger atomic transaction?
   - What if the underlying token contract has a callback mechanism?
   - What if the blockchain undergoes a reorg during a time-sensitive operation?
   - What if a dependency contract is paused, upgraded, or self-destructed?

**KNOWN VULNERABILITY PATTERNS TO TRANSCEND** (do NOT just list these, go deeper):
{known_vulns_context}

For each hypothesis, provide:
- **Title**: Descriptive name for the potential vulnerability
- **Hypothesis**: Clear statement of what could go wrong
- **Attack Narrative**: Step-by-step transaction sequence to exploit
- **Affected Functions**: Specific functions involved
- **Preconditions**: What must be true for the attack to work
- **Complexity**: How complex is the attack (Low/Medium/High)
- **Impact**: What would a successful exploit achieve
- **Novelty Reasoning**: Why this goes beyond known patterns
- **Investigation Steps**: How to verify if this hypothesis is correct
- **Related CWEs**: Closest CWE categories (may not map perfectly)

Generate at least 10 hypotheses, prioritized by impact and feasibility. Focus on hypotheses that represent TRUE 0-day potential - things that no scanner would find and most auditors would miss.
"""
        ),
        ell.user(
            "I understand the gravity of this task. I will generate truly novel hypotheses by reasoning about emergent behaviors, invariant violations, and attack chains that transcend known patterns. Each hypothesis will be actionable and grounded in the specific contract architecture."
        ),
        ell.user(
            f"Contract Decomposition:\n{contract_profile}\n\nAttack Surface Mapping:\n{attack_surfaces}\n\nGenerate novel vulnerability hypotheses. Output as JSON array in ```json``` blocks."
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.4)
def invoke_discovery_prompt_synthesis(
    contract_profile: str,
    attack_surfaces: str,
    hypotheses: str,
    protocol_type: str,
):
    """Synthesize all analysis into structured discovery prompts and investigation guides."""
    return [
        ell.system(
            "You are Axiom, a master prompt engineer and smart contract security researcher. Your specialty is creating precise, actionable prompts that guide LLM agents to discover 0-day vulnerabilities in smart contracts. Your prompts have been used to find critical bugs in Aave, Compound, Uniswap, and other major protocols before they were exploited. You understand that the quality of the prompt determines the quality of the vulnerability discovery."
        ),
        ell.user(
            f"""Based on the complete analysis below, synthesize a comprehensive set of DISCOVERY PROMPTS and INVESTIGATION GUIDES. These will be used by LLM agents and security researchers to systematically hunt for 0-day vulnerabilities in this specific contract and protocol type ({protocol_type}).

**REQUIREMENTS FOR EACH DISCOVERY PROMPT**:

Each prompt must be:
- Self-contained (usable without additional context)
- Specific to THIS contract's architecture and patterns
- Focused on a particular attack angle or hypothesis
- Actionable (researcher knows exactly what to investigate)
- Non-trivial (beyond what automated tools check)

**PROMPT CATEGORIES TO GENERATE**:

1. **INVARIANT VERIFICATION PROMPTS** (3-5 prompts):
   Create prompts that guide analysis of specific mathematical and state invariants.
   Each prompt should:
   - State the invariant clearly
   - Provide the relevant code context
   - Ask for construction of a violating transaction sequence
   - Include specific edge cases to consider

2. **CROSS-FUNCTION INTERACTION PROMPTS** (3-5 prompts):
   Create prompts that guide analysis of how functions interact through shared state.
   Each prompt should:
   - Identify the specific function pairs/groups to analyze
   - Describe the shared state variables
   - Ask for state corruption scenarios
   - Include the ordering constraints to consider

3. **ECONOMIC ATTACK PROMPTS** (3-5 prompts):
   Create prompts focused on economic/DeFi-specific attack vectors.
   Each prompt should:
   - Describe the economic mechanism
   - Provide relevant calculation code
   - Ask for manipulation scenarios with flash loans
   - Include specific numerical edge cases

4. **COMPOSABILITY ATTACK PROMPTS** (2-3 prompts):
   Create prompts for cross-protocol attack chains.
   Each prompt should:
   - Describe how this contract fits in the DeFi ecosystem
   - Identify external dependencies
   - Ask for multi-protocol attack scenarios
   - Include specific DeFi primitives to combine

5. **EVM EDGE CASE PROMPTS** (2-3 prompts):
   Create prompts for low-level EVM exploitation.
   Each prompt should:
   - Identify specific low-level patterns in the code
   - Provide EVM-level context
   - Ask for edge case construction
   - Include gas, memory, and storage considerations

6. **UPGRADE/PROXY PROMPTS** (if applicable, 1-2 prompts):
   Create prompts for upgrade-related vulnerabilities.

7. **META-INVESTIGATION GUIDE**:
   A comprehensive roadmap that:
   - Prioritizes which hypotheses to investigate first
   - Describes the tools and techniques needed for each
   - Provides a testing methodology (unit tests, fork tests, formal verification)
   - Suggests specific Foundry/Hardhat test scenarios to write
   - Includes invariant test suggestions for fuzzing
   - Outlines how to chain multiple findings together

**FORMAT FOR EACH PROMPT**:
```
{{
  "id": <number>,
  "category": "<prompt category>",
  "title": "<descriptive title>",
  "system_context": "<system prompt to set LLM context>",
  "analysis_prompt": "<the actual discovery prompt with full contract context embedded>",
  "focus_areas": ["<specific areas to investigate>"],
  "contract_context": "<relevant code snippets to include>",
  "investigation_guide": ["<step-by-step investigation instructions>"]
}}
```

The prompts should be usable DIRECTLY - an LLM receiving one of these prompts should be able to conduct meaningful vulnerability analysis without any additional context.
"""
        ),
        ell.user(
            "I will synthesize everything into prompts of the highest quality - each one a precision instrument for 0-day discovery. Every prompt will be self-contained, specific, and designed to reveal vulnerabilities that resist discovery through conventional methods."
        ),
        ell.user(
            f"Contract Decomposition:\n{contract_profile}\n\nAttack Surfaces:\n{attack_surfaces}\n\nVulnerability Hypotheses:\n{hypotheses}\n\nGenerate the complete set of discovery prompts and the meta-investigation guide. Output as JSON with two top-level keys: 'discovery_prompts' (array) and 'investigation_roadmap' (array of steps). Wrap in ```json``` blocks."
        ),
    ]


@ell.simple(model=MODEL, client=CLIENT, temperature=0.3)
def invoke_known_vulns_synthesis(dataset_context: str, protocol_type: str):
    """Synthesize known vulnerability patterns relevant to the target protocol type from the dataset."""
    return [
        ell.system(
            "You are Axiom, an AI expert in smart contract vulnerability taxonomy. You have deep knowledge of all known vulnerability patterns in EVM smart contracts and understand which patterns are most relevant to specific protocol types."
        ),
        ell.user(
            f"""Given the following vulnerability data from real-world audit reports and the target protocol type '{protocol_type}', synthesize a comprehensive summary of:

1. The most common vulnerability patterns found in {protocol_type} protocols
2. The most CRITICAL (high-impact) vulnerabilities specific to {protocol_type}
3. Known attack vectors that are unique to {protocol_type} architecture
4. Vulnerability patterns that auditors frequently miss in {protocol_type}
5. Recent (2023-2025) novel exploits against {protocol_type} protocols in the wild

This summary will be used as context for generating NOVEL hypotheses - the goal is to understand what is ALREADY KNOWN so we can reason about what is NOT YET KNOWN.

Dataset context:
{dataset_context}

Output a structured summary as plain text, organized by category. Be thorough but concise. Focus on the patterns most relevant to {protocol_type}.
"""
        ),
        ell.user(
            "I will synthesize the known vulnerability landscape for this protocol type, providing the foundation needed to reason beyond known patterns."
        ),
        ell.user(
            f"Begin synthesis for protocol type: {protocol_type}"
        ),
    ]
