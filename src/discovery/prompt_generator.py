"""
Prompt Generator - Synthesizes all analysis into actionable discovery prompts
and investigation guides for 0-day vulnerability hunting.

This is the final stage of the discovery pipeline. It takes:
- Contract structural profile
- Attack surface mappings
- Vulnerability hypotheses
- Known vulnerability patterns

And produces:
- Self-contained discovery prompts (usable by LLM agents)
- Investigation guides (usable by human researchers)
- Testing roadmaps (specific test scenarios to implement)
"""

import re
import json
import time
from typing import List, Dict, Optional
from loguru import logger
from pydantic import BaseModel

from core.models import DiscoveryPrompt, DiscoveryReport, ContractProfile
from core.invoker import (
    invoke_discovery_prompt_synthesis,
    MAX_RETRIES,
    INTERVAL,
)
from vendor.commentjson import commentjson


class PromptGenerator(BaseModel):
    """
    Generates structured discovery prompts and investigation guides
    from the complete analysis pipeline output.
    """

    class Config:
        arbitrary_types_allowed = True

    def generate(
        self,
        contract_profile_text: str,
        attack_surfaces: str,
        hypotheses: str,
        protocol_type: str,
        source_code: str,
    ) -> Dict:
        """
        Generate complete discovery prompts and investigation roadmap.

        Returns dict with keys: discovery_prompts, investigation_roadmap
        """
        # Invoke the LLM synthesis
        raw_output = self._invoke_synthesis(
            contract_profile_text,
            attack_surfaces,
            hypotheses,
            protocol_type,
        )

        # Parse the output
        result = self._parse_output(raw_output)

        # Enhance prompts with embedded source code context
        if result.get("discovery_prompts"):
            result["discovery_prompts"] = self._embed_source_context(
                result["discovery_prompts"], source_code
            )

        # Add meta-investigation prompts that are always relevant
        meta_prompts = self._generate_meta_prompts(
            protocol_type, contract_profile_text, source_code
        )
        if result.get("discovery_prompts"):
            result["discovery_prompts"].extend(meta_prompts)
        else:
            result["discovery_prompts"] = meta_prompts

        return result

    def _invoke_synthesis(
        self,
        contract_profile: str,
        attack_surfaces: str,
        hypotheses: str,
        protocol_type: str,
    ) -> str:
        """Call LLM to synthesize discovery prompts."""
        retry = 0
        while retry < MAX_RETRIES:
            try:
                result = invoke_discovery_prompt_synthesis(
                    contract_profile,
                    attack_surfaces,
                    hypotheses,
                    protocol_type,
                )
                if result and len(result) > 200:
                    return result
                retry += 1
                logger.warning(
                    "Prompt synthesis returned insufficient data, retry {}/{}",
                    retry, MAX_RETRIES,
                )
            except Exception as e:
                retry += 1
                backoff = INTERVAL * retry
                logger.error(
                    "Prompt synthesis error: {}, retry {}/{} after {}s",
                    e, retry, MAX_RETRIES, backoff,
                )
                if retry < MAX_RETRIES:
                    time.sleep(backoff)

        logger.error("Failed prompt synthesis after {} retries", MAX_RETRIES)
        return ""

    def _parse_output(self, raw_output: str) -> Dict:
        """Parse the LLM output into structured prompts and roadmap."""
        result = {
            "discovery_prompts": [],
            "investigation_roadmap": [],
        }

        if not raw_output:
            return result

        # Try to extract JSON
        parsed = self._extract_json(raw_output)
        if parsed:
            if isinstance(parsed, dict):
                result["discovery_prompts"] = parsed.get("discovery_prompts", [])
                result["investigation_roadmap"] = parsed.get(
                    "investigation_roadmap", []
                )
            return result

        # Fallback: treat the raw output as a single comprehensive prompt
        result["discovery_prompts"] = [
            {
                "id": 0,
                "category": "comprehensive",
                "title": "Full Discovery Analysis",
                "system_context": "You are an elite smart contract security researcher hunting for 0-day vulnerabilities.",
                "analysis_prompt": raw_output,
                "focus_areas": ["all areas"],
                "contract_context": "",
                "investigation_guide": [
                    "Review the complete analysis output",
                    "Identify the highest-impact hypotheses",
                    "Construct proof-of-concept test cases",
                ],
            }
        ]
        return result

    def _extract_json(self, text: str) -> Optional[dict]:
        """Extract JSON from LLM response text."""
        pattern = re.compile(
            r"```(?:json\s+)?(\{.*?\})```", re.DOTALL
        )
        match = pattern.search(text)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                try:
                    return commentjson.loads(match.group(1))
                except Exception:
                    pass

        # Try the broader match with array
        pattern2 = re.compile(
            r"```(?:json\s+)?([\[{].*?[\]}])```", re.DOTALL
        )
        match2 = pattern2.search(text)
        if match2:
            try:
                parsed = json.loads(match2.group(1))
                if isinstance(parsed, list):
                    return {"discovery_prompts": parsed, "investigation_roadmap": []}
                return parsed
            except Exception:
                pass

        # Try parsing entire text
        try:
            return json.loads(text)
        except Exception:
            pass
        return None

    def _embed_source_context(
        self, prompts: List[Dict], source_code: str
    ) -> List[Dict]:
        """
        For each discovery prompt, embed relevant source code snippets
        to make the prompt self-contained.
        """
        for prompt in prompts:
            if not prompt.get("contract_context") or prompt["contract_context"] == "":
                # Embed a truncated version of the source
                if len(source_code) > 3000:
                    prompt["contract_context"] = (
                        source_code[:3000] + "\n// ... (truncated)"
                    )
                else:
                    prompt["contract_context"] = source_code
        return prompts

    def _generate_meta_prompts(
        self, protocol_type: str, profile_text: str, source_code: str
    ) -> List[Dict]:
        """
        Generate universally-applicable meta-investigation prompts that reason
        about value conservation from first principles — no pattern labels,
        no traditional checklists.
        """
        source_snippet = source_code[:2000] if len(source_code) > 2000 else source_code

        meta_prompts = [
            {
                "id": 9000,
                "category": "value_conservation_audit",
                "title": "Complete Value Conservation Verification",
                "system_context": (
                    "You are investigating whether this smart contract maintains "
                    "perfect conservation of value — that no transaction sequence "
                    "allows an unprivileged caller to extract more than they put in."
                ),
                "analysis_prompt": (
                    f"Given this contract, derive every value-conservation invariant "
                    f"that must hold for the protocol to be solvent. Then, for each "
                    f"invariant, attempt to construct a transaction sequence that "
                    f"violates it.\n\n"
                    f"Step 1: List every state variable or mapping that represents a "
                    f"claim on value (balances, shares, debts, rewards, allowances).\n\n"
                    f"Step 2: For each, write a mathematical equation that relates the "
                    f"sum of internal claims to actual held value. Example: "
                    f"sum(userShares[i] * pricePerShare) <= token.balanceOf(this)\n\n"
                    f"Step 3: For each equation, find every code path that modifies "
                    f"any variable in the equation. Check: after that code path "
                    f"completes, does the equation still hold? What about DURING "
                    f"execution (e.g. after line N but before line M)?\n\n"
                    f"Step 4: For each potential break, write a concrete Foundry test:\n"
                    f"  - Set up initial state\n"
                    f"  - Execute the violating transaction sequence\n"
                    f"  - Assert that the attacker's balance increased net of costs\n\n"
                    f"Contract:\n```solidity\n{source_snippet}\n```"
                ),
                "focus_areas": [
                    "Sum of internal claims vs actual balance",
                    "Mid-execution state where invariant temporarily breaks",
                    "Transaction sequences that permanently shift value",
                    "Rates/multipliers that can be distorted before value transfer",
                ],
                "contract_context": source_snippet,
                "investigation_guide": [
                    "Enumerate every (internal_record, actual_balance) pair",
                    "Write the conservation equation for each pair",
                    "For every function that modifies any term, check the equation holds after completion",
                    "Check for windows during execution where the equation is broken and external calls fire",
                    "Implement as Foundry invariant_* tests with handler functions calling every public function",
                    "Run: forge test --match-test invariant -vvvv — any failure = potential drain",
                ],
            },
            {
                "id": 9001,
                "category": "stale_state_extraction",
                "title": "Value Extraction Through Stale State Windows",
                "system_context": (
                    "You are investigating whether there are moments during this "
                    "contract's execution when internal accounting does not match "
                    "reality, and whether a caller can act on that stale state to "
                    "extract value."
                ),
                "analysis_prompt": (
                    f"Map every point in this contract where execution is handed "
                    f"to external code (external calls, token transfers, callbacks, "
                    f"delegate calls) and determine: at that exact moment, which "
                    f"internal state variables are stale (not yet updated to reflect "
                    f"the current operation)?\n\n"
                    f"For each such window:\n"
                    f"1. What state is stale and what would the correct value be?\n"
                    f"2. Can the external code (or a contract it calls back into) read "
                    f"   or act on the stale state?\n"
                    f"3. If so, what value can be extracted by acting on stale state?\n"
                    f"4. Write the exact sequence: which function to call, what happens "
                    f"   during the callback, what to call back into, and what the net "
                    f"   extraction is.\n\n"
                    f"Do NOT limit yourself to the contract calling back into itself. "
                    f"Consider: the contract calls token.transfer(), the token contract "
                    f"calls back to a third contract, which reads a view function on "
                    f"this contract that returns stale data, and uses that stale data "
                    f"to make a favorable trade.\n\n"
                    f"Contract:\n```solidity\n{source_snippet}\n```"
                ),
                "focus_areas": [
                    "Every external call and which state is stale at that moment",
                    "View functions that can be called during stale windows",
                    "Multi-contract callback chains that exploit stale reads",
                    "State update ordering — what is updated before vs after external calls",
                ],
                "contract_context": source_snippet,
                "investigation_guide": [
                    "For every external call: list state modified BEFORE and AFTER the call",
                    "For every view function: check if it returns different values before vs after the external call",
                    "Deploy a malicious contract that receives the callback and re-enters or queries stale state",
                    "Calculate net value extraction for the stale-state read scenario",
                    "Write a Foundry test: deploy attacker contract, trigger the stale window, assert profit > 0",
                ],
            },
            {
                "id": 9002,
                "category": "arithmetic_value_leak",
                "title": "Value Leakage Through Computational Imprecision",
                "system_context": (
                    "You are investigating whether the mathematical computations "
                    "in this contract — division truncation, multiplication ordering, "
                    "rate calculations — create a systematic leak where small amounts "
                    "of value can be repeatedly extracted or where a single large "
                    "computation produces an exploitable rounding windfall."
                ),
                "analysis_prompt": (
                    f"Trace every arithmetic operation in this contract that affects "
                    f"how much value a caller receives or must pay. For each:\n\n"
                    f"1. Does the computation TRUNCATE in the caller's favor or the "
                    f"   protocol's favor? (Solidity division truncates toward zero — "
                    f"   does this help the caller or the protocol in each case?)\n\n"
                    f"2. Can the caller choose inputs that MAXIMIZE truncation in "
                    f"   their favor? (e.g. deposit an amount that, divided by the "
                    f"   rate, truncates to give them one extra share; or withdraw "
                    f"   an amount where the fee rounds to zero)\n\n"
                    f"3. Is there a rate, price, or multiplier that the caller can "
                    f"   DISTORT before the computation? (e.g. donate tokens to "
                    f"   inflate pricePerShare, then withdraw at the inflated rate "
                    f"   — does the contract use the inflated rate naively?)\n\n"
                    f"4. Can the caller perform the operation MANY TIMES with small "
                    f"   amounts to accumulate rounding in their favor? What is the "
                    f"   profit after 1000 iterations? After 1M?\n\n"
                    f"5. For the first-ever operation (empty pool, zero shares, zero "
                    f"   balance): is there an initialization edge case where the "
                    f"   computation produces a wildly incorrect result? Can the caller "
                    f"   exploit this to establish a favorable rate permanently?\n\n"
                    f"For each finding, provide:\n"
                    f"- The exact formula from the code\n"
                    f"- Concrete numbers: input X → output Y → attacker profit Z\n"
                    f"- A Foundry test skeleton\n\n"
                    f"Contract:\n```solidity\n{source_snippet}\n```"
                ),
                "focus_areas": [
                    "Every division and who benefits from the truncation",
                    "Rates/prices the caller can inflate before a value-transfer computation",
                    "Repeated small operations that accumulate rounding profit",
                    "First-operation / empty-state edge cases in value calculations",
                ],
                "contract_context": source_snippet,
                "investigation_guide": [
                    "List every division, modulo, and mulDiv operation in the contract",
                    "For each: determine if truncation favors caller or protocol",
                    "Test with: amount=1, amount=2, amount=type(uint256).max, amount just below a rounding boundary",
                    "Test the empty-pool / first-depositor scenario with a donation before the second deposit",
                    "Write a Foundry test that loops the operation 1000 times and checks cumulative profit",
                ],
            },
        ]

        return meta_prompts

    def build_report(
        self,
        target_path: str,
        contract_profiles: List[Dict],
        attack_surfaces_raw: str,
        hypotheses_raw: str,
        prompts_result: Dict,
        known_vulns_context: str,
    ) -> DiscoveryReport:
        """Build the final DiscoveryReport from all pipeline outputs."""
        report = DiscoveryReport(
            target_path=target_path,
            contract_profiles=contract_profiles,
            attack_surfaces=self._safe_parse_list(attack_surfaces_raw),
            vulnerability_hypotheses=self._safe_parse_list(hypotheses_raw),
            discovery_prompts=prompts_result.get("discovery_prompts", []),
            meta_analysis=known_vulns_context,
            investigation_roadmap=prompts_result.get("investigation_roadmap", []),
        )
        return report

    def _safe_parse_list(self, raw: str) -> List[Dict]:
        """Try to parse a string as a JSON list of dicts."""
        if not raw:
            return []

        # Try extracting JSON array
        pattern = re.compile(r"```(?:json\s+)?\[(.+?)\]```", re.DOTALL)
        match = pattern.search(raw)
        if match:
            try:
                return json.loads("[" + match.group(1) + "]")
            except Exception:
                pass

        # Try extracting JSON object with array value
        pattern2 = re.compile(r"```(?:json\s+)?(\{.*?\})```", re.DOTALL)
        match2 = pattern2.search(raw)
        if match2:
            try:
                parsed = json.loads(match2.group(1))
                if isinstance(parsed, dict):
                    # Return the first list value found
                    for v in parsed.values():
                        if isinstance(v, list):
                            return v
                    return [parsed]
            except Exception:
                pass

        # Store raw text as single entry
        return [{"raw_analysis": raw}]
