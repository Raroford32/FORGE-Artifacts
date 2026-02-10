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
        Generate always-applicable meta-investigation prompts that probe
        for vulnerability classes that are universally relevant regardless
        of specific contract analysis.
        """
        source_snippet = source_code[:2000] if len(source_code) > 2000 else source_code

        meta_prompts = [
            {
                "id": 9000,
                "category": "invariant_fuzzing",
                "title": "Invariant Fuzzing Strategy Generator",
                "system_context": (
                    "You are an expert in property-based testing and fuzzing for smart contracts. "
                    "You specialize in writing Foundry invariant tests that catch critical vulnerabilities."
                ),
                "analysis_prompt": (
                    f"Given the following {protocol_type} smart contract, generate a comprehensive set of "
                    f"invariant properties that should ALWAYS hold true. For each invariant:\n"
                    f"1. State the invariant in plain English\n"
                    f"2. Express it as a Solidity assertion\n"
                    f"3. Describe a scenario where it could be violated\n"
                    f"4. Write a Foundry invariant test function skeleton\n\n"
                    f"Focus on:\n"
                    f"- Balance invariants (sum of all user balances == total supply)\n"
                    f"- State machine invariants (valid state transitions only)\n"
                    f"- Economic invariants (no value creation from nothing)\n"
                    f"- Access control invariants (privileges only through intended paths)\n"
                    f"- Ordering invariants (operations must happen in correct sequence)\n\n"
                    f"Contract:\n```solidity\n{source_snippet}\n```"
                ),
                "focus_areas": [
                    "Balance consistency",
                    "State machine correctness",
                    "Economic soundness",
                    "Access control integrity",
                ],
                "contract_context": source_snippet,
                "investigation_guide": [
                    "Implement each invariant as a Foundry invariant_* test function",
                    "Configure handler functions that call every external/public function",
                    "Run with high iteration count: forge test --match-test invariant -vvv",
                    "Any invariant violation indicates a potential vulnerability",
                    "Analyze the call sequence that caused the violation",
                ],
            },
            {
                "id": 9001,
                "category": "cross_contract_reentrancy",
                "title": "Deep Reentrancy Surface Analysis",
                "system_context": (
                    "You are an expert in reentrancy vulnerabilities in EVM smart contracts. "
                    "You understand all forms: classic, cross-function, cross-contract, read-only, "
                    "and governance reentrancy. You can identify reentrancy surfaces that "
                    "automated tools like Slither consistently miss."
                ),
                "analysis_prompt": (
                    f"Analyze the following smart contract for ALL forms of reentrancy vulnerability. "
                    f"Go far beyond the check-effects-interactions pattern. Specifically analyze:\n\n"
                    f"1. **View Function Reentrancy**: Are there view functions that read state that "
                    f"could be inconsistent during a callback? Could another protocol call these "
                    f"view functions during a callback from this contract?\n\n"
                    f"2. **Cross-Function Reentrancy**: If function A makes an external call, "
                    f"could an attacker reenter through function B and exploit state that A "
                    f"has partially updated?\n\n"
                    f"3. **Cross-Contract Reentrancy**: Does this contract interact with other "
                    f"contracts that could trigger callbacks? Consider ERC777 hooks, ERC1155 "
                    f"hooks, Uniswap callbacks, flash loan callbacks, etc.\n\n"
                    f"4. **Governance Reentrancy**: Could a governance action be executed during "
                    f"a callback that changes parameters mid-operation?\n\n"
                    f"5. **Transient Storage Reentrancy**: If the contract uses EIP-1153 transient "
                    f"storage for reentrancy guards, are there edge cases?\n\n"
                    f"For each potential reentrancy path found:\n"
                    f"- Describe the exact call chain\n"
                    f"- Identify the inconsistent state window\n"
                    f"- Provide a concrete attack scenario\n"
                    f"- Estimate the impact\n\n"
                    f"Contract:\n```solidity\n{source_snippet}\n```"
                ),
                "focus_areas": [
                    "External calls before state updates",
                    "View function state consistency",
                    "Cross-function shared state",
                    "Token callback hooks",
                    "Flash loan callbacks",
                ],
                "contract_context": source_snippet,
                "investigation_guide": [
                    "Map every external call and the state it occurs in",
                    "For each external call, list all state that has been modified vs not yet modified",
                    "Check if any view function could return incorrect data during the callback window",
                    "Build a reentrancy attack contract targeting identified paths",
                    "Test with both ERC20 and ERC777 tokens if applicable",
                ],
            },
            {
                "id": 9002,
                "category": "precision_and_rounding",
                "title": "Mathematical Precision Exploit Analysis",
                "system_context": (
                    "You are a mathematician and smart contract auditor specializing in "
                    "numerical precision vulnerabilities. You understand fixed-point arithmetic, "
                    "rounding behavior in Solidity, and how precision errors accumulate over "
                    "many operations to create exploitable conditions."
                ),
                "analysis_prompt": (
                    f"Perform a thorough mathematical precision analysis of this smart contract. "
                    f"Specifically investigate:\n\n"
                    f"1. **Rounding Direction**: For every division operation, determine if it rounds "
                    f"in the direction that favors the protocol or the user. Identify any operation "
                    f"where rounding could be exploited (e.g., round down on deposit, round up on withdraw).\n\n"
                    f"2. **Precision Loss Chains**: Identify sequences of operations where precision "
                    f"loss accumulates. Calculate worst-case precision loss for realistic scenarios.\n\n"
                    f"3. **First Depositor / Share Inflation**: If this contract uses share-based "
                    f"accounting (like ERC4626), analyze the first depositor attack surface. "
                    f"Can an attacker inflate share price through donations?\n\n"
                    f"4. **Fee Calculation Edge Cases**: Analyze all fee calculations for:\n"
                    f"   - Zero-fee edge cases (amount too small to generate a fee)\n"
                    f"   - Fee-on-fee compounding errors\n"
                    f"   - Fee bypass through specific amounts\n\n"
                    f"5. **Exchange Rate Manipulation**: If the contract has any exchange rate "
                    f"(shares/assets, collateral/debt), analyze how it can be manipulated "
                    f"and what the impact would be.\n\n"
                    f"6. **Overflow/Underflow in Unchecked Blocks**: Identify all unchecked "
                    f"blocks and analyze whether overflow/underflow could occur.\n\n"
                    f"For each issue found, provide:\n"
                    f"- The exact mathematical formula involved\n"
                    f"- A concrete numerical example showing the exploit\n"
                    f"- The profit an attacker could extract\n"
                    f"- Suggested fix\n\n"
                    f"Contract:\n```solidity\n{source_snippet}\n```"
                ),
                "focus_areas": [
                    "Division rounding direction",
                    "Share/rate inflation",
                    "Precision loss accumulation",
                    "Fee calculation edge cases",
                    "Unchecked arithmetic",
                ],
                "contract_context": source_snippet,
                "investigation_guide": [
                    "List every arithmetic operation (especially division) in the contract",
                    "For each division, determine if rounding favors user or protocol",
                    "Test with extreme values: very small amounts, very large amounts, 0, 1, type(uint256).max",
                    "Calculate precision loss for realistic usage patterns over many operations",
                    "Write Foundry tests with specific numerical edge cases",
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
