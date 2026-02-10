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
        Generate comprehensive, framework-grounded investigation prompts.

        Each meta-prompt is a complete investigation briefing that carries
        the reasoning framework, teaches the analyst HOW TO THINK about
        the specific investigation area, and provides everything needed
        to reach a definitive conclusion.
        """
        from discovery.framework import (
            MISSION, CORE_PRINCIPLES, SYSTEM_IDENTITY, DRAINAGE_MECHANICS,
        )

        source_snippet = source_code[:4000] if len(source_code) > 4000 else source_code

        meta_prompts = [
            {
                "id": 9000,
                "category": "value_conservation_audit",
                "title": "Complete Value Conservation Verification",
                "system_context": SYSTEM_IDENTITY,
                "analysis_prompt": (
                    f"MISSION: {MISSION}\n\n"
                    f"You are conducting a complete value-conservation audit of the "
                    f"following smart contract. This is the most fundamental "
                    f"investigation: if conservation holds, no drain is possible; "
                    f"if it breaks anywhere, that break is an exploit.\n\n"
                    f"REASONING FRAMEWORK:\n"
                    f"{CORE_PRINCIPLES}\n\n"
                    f"YOUR INVESTIGATION:\n\n"
                    f"Step 1 — IDENTIFY EVERY FORM OF VALUE\n"
                    f"Read the contract and list every state variable or mapping that "
                    f"represents a claim on economic value. For each, describe in "
                    f"plain language what it tracks and how it relates to actual "
                    f"tokens/ETH held by the contract.\n\n"
                    f"Step 2 — DERIVE CONSERVATION EQUATIONS\n"
                    f"For each value type, write the mathematical equation that MUST "
                    f"hold for the protocol to be solvent. Use the actual variable "
                    f"names from the code. Be specific:\n"
                    f"  BAD: 'balances should be consistent'\n"
                    f"  GOOD: 'sum(balances[u] for all u) == totalSupply AND "
                    f"totalSupply <= token.balanceOf(address(this))'\n\n"
                    f"Step 3 — TEST EACH EQUATION AGAINST EVERY CODE PATH\n"
                    f"For every function that modifies any variable in any equation:\n"
                    f"  (a) Does the equation hold AFTER the function completes?\n"
                    f"  (b) Does the equation hold DURING execution — specifically, "
                    f"at every point where an external call occurs?\n"
                    f"  (c) If the equation breaks during execution, can the attacker "
                    f"gain execution in that window? (Through callbacks, re-entry, "
                    f"or a contract they deployed that receives a call.)\n\n"
                    f"Step 4 — CONSTRUCT VIOLATION SEQUENCES\n"
                    f"For each potential break, write a concrete transaction sequence:\n"
                    f"  - What the attacker deploys (if anything)\n"
                    f"  - What functions they call, in what order, with what arguments\n"
                    f"  - What happens during any callbacks\n"
                    f"  - What the attacker's balance is before and after\n"
                    f"  - The Foundry test that proves the violation\n\n"
                    f"Contract:\n```solidity\n{source_snippet}\n```"
                ),
                "focus_areas": [
                    "Conservation equations derived from actual state variables",
                    "Windows during execution where equations temporarily break",
                    "External calls that fire during broken-equation windows",
                    "Rates or multipliers an attacker can distort before value transfer",
                ],
                "contract_context": source_snippet,
                "investigation_guide": [
                    "List every (internal_claim, actual_balance) pair in the contract",
                    "Write each conservation equation using code variable names",
                    "For every function: trace which equation terms change and in what order",
                    "At every external call: check if any equation is temporarily violated",
                    "For each violation window: determine if attacker can gain execution",
                    "Write Foundry invariant tests: function invariant_conservation() checks all equations",
                    "Run: forge test --match-test invariant -vvvv with 10000+ runs",
                    "Any failure = confirmed drain vector — extract the call sequence from the failure",
                ],
            },
            {
                "id": 9001,
                "category": "stale_state_extraction",
                "title": "Value Extraction Through Stale State Windows",
                "system_context": SYSTEM_IDENTITY,
                "analysis_prompt": (
                    f"MISSION: {MISSION}\n\n"
                    f"You are investigating a specific class of conservation break: "
                    f"moments when the contract's internal state does not accurately "
                    f"reflect reality, and whether an attacker can act on the "
                    f"inaccurate state to extract value.\n\n"
                    f"WHY THIS MATTERS:\n"
                    f"Every drain in history involves the code's model diverging from "
                    f"reality (Principle 5 of the framework). The most common "
                    f"divergence happens DURING execution: the contract has updated "
                    f"variable A but not yet variable B, and at that exact moment "
                    f"it hands execution to external code. The external code — or "
                    f"anything it calls — can observe or act on the stale state.\n\n"
                    f"YOUR INVESTIGATION:\n\n"
                    f"1. MAP EVERY EXTERNAL CALL\n"
                    f"   For every point where this contract sends execution to external "
                    f"   code (token.transfer, token.transferFrom, low-level .call, "
                    f"   delegatecall, or any interface call), create a state snapshot:\n"
                    f"   - Which state variables have been UPDATED so far in this function?\n"
                    f"   - Which state variables have NOT YET been updated?\n"
                    f"   - What is the INTENDED final state vs the CURRENT partial state?\n\n"
                    f"2. IDENTIFY EXPLOITABLE WINDOWS\n"
                    f"   For each external call with stale state, determine:\n"
                    f"   - Can the recipient (or anything it calls) re-enter this contract?\n"
                    f"   - Can the recipient call a view function that returns stale data?\n"
                    f"   - Is any OTHER contract reading this contract's state (via view "
                    f"     functions) that would get incorrect data during this window?\n"
                    f"   - Can the attacker make a favorable trade on a DEX or lending "
                    f"     protocol using the stale data?\n\n"
                    f"3. CONSTRUCT EXTRACTION SEQUENCES\n"
                    f"   For each exploitable window:\n"
                    f"   - Attacker deploys contract C that will receive the callback\n"
                    f"   - C's receive/fallback/hook function does X during the stale window\n"
                    f"   - After the original function completes, the attacker has Y net profit\n"
                    f"   - Write the Foundry test with exact values\n\n"
                    f"DO NOT LIMIT TO SELF-REENTRANCY. Consider:\n"
                    f"  - Contract A calls token.transfer() → token calls attacker → "
                    f"    attacker queries Contract A's view function → gets stale data → "
                    f"    uses stale data to trade on DEX at favorable price\n"
                    f"  - Contract A calls B.withdraw() → B calls token.transfer() to "
                    f"    attacker → attacker calls A.deposit() with stale exchange rate\n\n"
                    f"Contract:\n```solidity\n{source_snippet}\n```"
                ),
                "focus_areas": [
                    "Every external call and the exact state snapshot at that moment",
                    "View functions that return different values during stale windows",
                    "Multi-hop callback chains that reach stale state indirectly",
                    "Update ordering: what changes before vs after each external call",
                ],
                "contract_context": source_snippet,
                "investigation_guide": [
                    "For each function: list every external call in execution order",
                    "At each external call: list state updated BEFORE and NOT YET updated",
                    "For each view function: check if return value differs during any stale window",
                    "Deploy attacker contract: receive callback → perform action on stale state",
                    "Test: attacker.balance_after - attacker.balance_before > 0",
                    "Also test: stale view function → use on external DEX/lending → profit",
                    "Write Foundry test with ReentrancyAttacker contract",
                ],
            },
            {
                "id": 9002,
                "category": "arithmetic_value_leak",
                "title": "Value Leakage Through Computational Imprecision",
                "system_context": SYSTEM_IDENTITY,
                "analysis_prompt": (
                    f"MISSION: {MISSION}\n\n"
                    f"You are investigating whether the mathematical computations in "
                    f"this contract create value leaks — places where the attacker "
                    f"can choose inputs that cause the arithmetic to favor them, "
                    f"or where they can distort a rate/price before it is used in "
                    f"a value-determining computation.\n\n"
                    f"WHY THIS MATTERS:\n"
                    f"Solidity integer arithmetic truncates division toward zero. This "
                    f"means every division is a potential leak: the question is whether "
                    f"the truncation favors the protocol or the caller, and whether the "
                    f"caller can choose inputs to maximize truncation in their favor. "
                    f"Beyond rounding, the attacker may be able to DISTORT the rate "
                    f"itself — inflate or deflate a price/exchange-rate before the "
                    f"contract uses it — creating a much larger extraction than "
                    f"rounding alone.\n\n"
                    f"YOUR INVESTIGATION:\n\n"
                    f"1. TRACE EVERY VALUE-AFFECTING COMPUTATION\n"
                    f"   For every arithmetic operation that affects how much value "
                    f"   a caller receives or must pay:\n"
                    f"   - What is the exact formula? (Copy from the code.)\n"
                    f"   - Does truncation favor the caller or the protocol?\n"
                    f"   - Can the caller choose inputs that maximize truncation?\n"
                    f"   - Example: deposit X tokens, receive Y shares where "
                    f"     Y = X * totalShares / totalAssets. If the attacker chooses X "
                    f"     such that the division truncates to give them 1 extra share...\n\n"
                    f"2. INVESTIGATE RATE DISTORTION\n"
                    f"   For every rate, price, or exchange ratio used in value computations:\n"
                    f"   - How is the rate calculated? (e.g. totalAssets / totalShares)\n"
                    f"   - Can the attacker influence any input to the rate? (donate tokens "
                    f"     to change totalAssets? flash-borrow to change pool reserves?)\n"
                    f"   - What happens if they distort the rate BEFORE a value transfer "
                    f"     and restore it AFTER?\n"
                    f"   - Calculate: rate_before, rate_after_distortion, value extracted\n\n"
                    f"3. INVESTIGATE FIRST-USE / EMPTY-STATE EDGE CASES\n"
                    f"   For the very first deposit, mint, or initialization:\n"
                    f"   - What happens when totalShares=0 or totalAssets=0?\n"
                    f"   - Can the attacker establish a favorable rate permanently?\n"
                    f"   - Classic: first depositor deposits 1 wei, donates 1M tokens, "
                    f"     second depositor deposits 999K tokens and gets 0 shares\n\n"
                    f"4. QUANTIFY ACCUMULATED LEAK\n"
                    f"   For each rounding leak: what is the profit after 1, 100, "
                    f"   1000, and 1M iterations? Is it gas-profitable? Can flash loans "
                    f"   amplify it?\n\n"
                    f"Contract:\n```solidity\n{source_snippet}\n```"
                ),
                "focus_areas": [
                    "Every division and who benefits from truncation",
                    "Rates/prices the attacker can distort before value computation",
                    "First-use / empty-state edge cases",
                    "Accumulated rounding leak over many iterations",
                ],
                "contract_context": source_snippet,
                "investigation_guide": [
                    "List every division, modulo, and mulDiv in the contract",
                    "For each: who benefits from truncation (caller or protocol)?",
                    "Find every rate/price: how is it computed? can inputs be manipulated?",
                    "Test rate distortion: donate tokens → execute at distorted rate → measure profit",
                    "Test empty-state: first depositor → donation → second depositor gets 0 shares",
                    "Test accumulation: loop the operation 1000 times → measure cumulative profit",
                    "Use Foundry with exact uint256 values — precision matters",
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
