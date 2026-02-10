"""
Contract Analyzer - Deep structural decomposition of smart contracts.

Performs exhaustive analysis of Solidity source code to extract:
- State architecture, function surfaces, access control topology
- Value flow maps, external dependencies, dangerous patterns
- Protocol type classification and invariant identification

This is the first stage of the discovery pipeline, feeding into
attack surface mapping and hypothesis generation.
"""

import os
import re
import json
import time
import tiktoken
from typing import List, Dict, Optional, Tuple
from loguru import logger
from pydantic import BaseModel, TypeAdapter

from core.models import ContractProfile, StateVariable, FunctionSignature
from core.invoker import (
    invoke_contract_decompose,
    MAX_RETRIES,
    INTERVAL,
)
from vendor.commentjson import commentjson


class ContractAnalyzer(BaseModel):
    """Analyzes smart contracts to produce deep structural profiles."""

    class Config:
        arbitrary_types_allowed = True

    def analyze_file(self, filepath: str) -> Tuple[ContractProfile, str]:
        """
        Analyze a single Solidity file and return its structural profile.

        Returns:
            Tuple of (ContractProfile, raw_decomposition_json_string)
        """
        source_code = self._read_source(filepath)
        if not source_code:
            logger.error("Failed to read source file: {}", filepath)
            return ContractProfile(file_path=filepath), ""

        profile = ContractProfile(
            file_path=filepath,
            raw_source=source_code,
        )

        # Static pre-analysis (regex-based, no LLM needed)
        self._static_preanalysis(profile, source_code)

        # Deep LLM-driven decomposition
        decomposition = self._invoke_decomposition(source_code)

        if decomposition:
            self._enrich_profile(profile, decomposition)

        return profile, decomposition

    def analyze_directory(self, dirpath: str) -> List[Tuple[ContractProfile, str]]:
        """Analyze all .sol files in a directory."""
        results = []
        for root, _dirs, files in os.walk(dirpath):
            for f in sorted(files):
                if f.endswith(".sol"):
                    filepath = os.path.join(root, f)
                    logger.info("Analyzing contract: {}", filepath)
                    result = self.analyze_file(filepath)
                    results.append(result)
        return results

    def _read_source(self, filepath: str) -> Optional[str]:
        """Read Solidity source code from file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error("Error reading {}: {}", filepath, e)
            return None

    def _static_preanalysis(self, profile: ContractProfile, source: str):
        """
        Fast regex-based pre-analysis to populate basic profile fields
        before LLM decomposition. This gives the LLM better context and
        provides fallback data if LLM analysis is incomplete.
        """
        # Pragma
        pragma_match = re.search(r"pragma\s+solidity\s+([^;]+);", source)
        if pragma_match:
            profile.compiler_pragma = pragma_match.group(1).strip()

        # Contract name
        contract_match = re.search(
            r"contract\s+(\w+)\s*(is\s+[^{]+)?{", source
        )
        if contract_match:
            profile.contract_name = contract_match.group(1)
            if contract_match.group(2):
                inheritance = contract_match.group(2).replace("is", "").strip()
                profile.inheritance_chain = [
                    c.strip() for c in inheritance.split(",")
                ]

        # Imports
        imports = re.findall(r'import\s+[^;]*["\'](.*?)["\']', source)
        profile.imported_contracts = imports

        # Dangerous patterns
        profile.uses_assembly = bool(re.search(r"\bassembly\s*{", source))
        profile.uses_delegatecall = "delegatecall" in source
        profile.uses_selfdestruct = "selfdestruct" in source or "suicide" in source
        profile.uses_create2 = "create2" in source

        # Token standards detection
        token_standards = []
        if re.search(r"IERC20|ERC20", source):
            token_standards.append("ERC20")
        if re.search(r"IERC721|ERC721", source):
            token_standards.append("ERC721")
        if re.search(r"IERC1155|ERC1155", source):
            token_standards.append("ERC1155")
        if re.search(r"IERC777|ERC777", source):
            token_standards.append("ERC777")
        if re.search(r"ERC4626", source):
            token_standards.append("ERC4626")
        profile.token_standards = token_standards

        # Upgradeability detection
        if any(
            kw in source
            for kw in [
                "Upgradeable",
                "UUPSUpgradeable",
                "TransparentUpgradeableProxy",
                "Initializable",
                "initializer",
                "delegatecall",
            ]
        ):
            profile.is_upgradeable = True
        if any(
            kw in source
            for kw in [
                "Proxy",
                "_implementation",
                "_fallback",
                "delegatecall",
            ]
        ):
            profile.is_proxy = True

        # Protocol type heuristic
        profile.protocol_type = self._classify_protocol_type(source)

        # Extract events
        events = re.findall(r"event\s+(\w+)\s*\(", source)
        profile.events = events

        # Extract modifiers
        modifiers = re.findall(r"modifier\s+(\w+)\s*[\({]", source)
        profile.modifiers = modifiers

        # Extract function signatures
        func_matches = re.finditer(
            r"function\s+(\w+)\s*\(([^)]*)\)\s*((?:(?:external|public|internal|private|view|pure|payable|virtual|override|returns\s*\([^)]*\)|\w+)\s*)*)",
            source,
        )
        for m in func_matches:
            sig = FunctionSignature(
                name=m.group(1),
                parameters=[p.strip() for p in m.group(2).split(",") if p.strip()],
            )
            qualifiers = m.group(3) if m.group(3) else ""
            if "external" in qualifiers:
                sig.visibility = "external"
            elif "public" in qualifiers:
                sig.visibility = "public"
            elif "internal" in qualifiers:
                sig.visibility = "internal"
            elif "private" in qualifiers:
                sig.visibility = "private"
            else:
                sig.visibility = "public"  # Solidity default
            sig.is_payable = "payable" in qualifiers
            # Extract modifier names from qualifiers
            mod_matches = re.findall(r"\b(\w+)\b", qualifiers)
            visibility_kws = {
                "external", "public", "internal", "private",
                "view", "pure", "payable", "virtual", "override", "returns",
            }
            sig.modifiers = [m for m in mod_matches if m not in visibility_kws]
            profile.functions.append(sig)

        # State variables
        var_pattern = re.compile(
            r"^\s*(mapping\s*\(.*?\)|[\w\[\]]+)\s+((?:public|private|internal|constant|immutable)\s+)*(\w+)\s*[;=]",
            re.MULTILINE,
        )
        for vm in var_pattern.finditer(source):
            sv = StateVariable(
                var_type=vm.group(1).strip(),
                visibility=vm.group(2).strip() if vm.group(2) else "internal",
                name=vm.group(3).strip(),
            )
            profile.state_variables.append(sv)

    def _classify_protocol_type(self, source: str) -> str:
        """Heuristic protocol type classification from source patterns."""
        source_lower = source.lower()
        indicators = {
            "lending": ["borrow", "lend", "collateral", "liquidat", "healthfactor", "ltv"],
            "dex_amm": ["swap", "addliquidity", "removeliquidity", "getamountout", "pool", "pair", "amm"],
            "yield_aggregator": ["vault", "strategy", "harvest", "compound", "yield", "erc4626"],
            "staking": ["stake", "unstake", "reward", "delegate", "epoch"],
            "bridge": ["bridge", "relay", "crosschain", "l1", "l2", "messenger"],
            "governance": ["proposal", "vote", "quorum", "governor", "timelock"],
            "nft_marketplace": ["listing", "auction", "bid", "royalt", "erc721", "erc1155"],
            "oracle": ["oracle", "pricefeed", "observation", "twap", "chainlink"],
            "token": ["transfer", "approve", "allowance", "mint", "burn", "totalsupply"],
        }
        scores = {}
        for ptype, keywords in indicators.items():
            score = sum(1 for kw in keywords if kw in source_lower)
            if score > 0:
                scores[ptype] = score

        if not scores:
            return "unknown"
        return max(scores, key=scores.get)

    def _invoke_decomposition(self, source_code: str) -> str:
        """
        Call the LLM for deep structural decomposition.
        Returns raw JSON string of the decomposition.
        """
        # Truncate very large contracts to fit context window
        enc = tiktoken.get_encoding("cl100k_base")
        token_count = len(enc.encode(source_code))
        if token_count > 12000:
            logger.warning(
                "Contract is {} tokens, truncating to ~12000 for decomposition",
                token_count,
            )
            tokens = enc.encode(source_code)[:12000]
            source_code = enc.decode(tokens)

        retry = 0
        while retry < MAX_RETRIES:
            try:
                result = invoke_contract_decompose(source_code)
                if result and len(result) > 50:
                    return result
                retry += 1
                logger.warning(
                    "Decomposition returned insufficient data, retry {}/{}",
                    retry, MAX_RETRIES,
                )
            except Exception as e:
                retry += 1
                backoff = INTERVAL * retry
                logger.error(
                    "Decomposition error: {}, retry {}/{} after {}s",
                    e, retry, MAX_RETRIES, backoff,
                )
                if retry < MAX_RETRIES:
                    time.sleep(backoff)

        logger.error("Failed to decompose contract after {} retries", MAX_RETRIES)
        return ""

    def _enrich_profile(self, profile: ContractProfile, decomposition: str):
        """
        Enrich the ContractProfile with data parsed from the LLM decomposition.
        Merges LLM insights with static pre-analysis, preferring LLM data when
        it provides more detail.
        """
        parsed = self._extract_json(decomposition)
        if not parsed:
            return

        # Enrich protocol type if LLM provides more specific classification
        if isinstance(parsed, dict):
            llm_protocol = parsed.get("protocol_type_classification", {})
            if isinstance(llm_protocol, dict) and llm_protocol.get("type"):
                profile.protocol_type = llm_protocol["type"]
            elif isinstance(llm_protocol, str) and llm_protocol:
                profile.protocol_type = llm_protocol

            # Enrich external dependencies
            ext_deps = parsed.get("external_dependency_map", {})
            if isinstance(ext_deps, dict):
                for key, val in ext_deps.items():
                    if isinstance(val, list):
                        profile.external_dependencies.extend(
                            [str(v) for v in val]
                        )
                    elif isinstance(val, str) and val != "n/a":
                        profile.external_dependencies.append(f"{key}: {val}")

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
        # Try parsing the entire text as JSON
        try:
            return json.loads(text)
        except Exception:
            pass
        return None

    def _calc_tokens(self, text: str) -> int:
        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))

    def profile_to_context(self, profile: ContractProfile) -> str:
        """Convert a ContractProfile to a text summary for use in subsequent prompts."""
        lines = [
            f"Contract: {profile.contract_name}",
            f"File: {profile.file_path}",
            f"Pragma: {profile.compiler_pragma}",
            f"Protocol Type: {profile.protocol_type}",
            f"Upgradeable: {profile.is_upgradeable}",
            f"Proxy: {profile.is_proxy}",
            f"Inheritance: {', '.join(profile.inheritance_chain)}",
            f"Token Standards: {', '.join(profile.token_standards)}",
            f"Uses Assembly: {profile.uses_assembly}",
            f"Uses Delegatecall: {profile.uses_delegatecall}",
            f"Uses Selfdestruct: {profile.uses_selfdestruct}",
            f"Uses CREATE2: {profile.uses_create2}",
            "",
            "--- State Variables ---",
        ]
        for sv in profile.state_variables:
            lines.append(f"  {sv.visibility} {sv.var_type} {sv.name}")

        lines.append("")
        lines.append("--- Functions ---")
        for fn in profile.functions:
            mods = f" [{', '.join(fn.modifiers)}]" if fn.modifiers else ""
            payable = " payable" if fn.is_payable else ""
            lines.append(
                f"  {fn.visibility}{payable} {fn.name}({', '.join(fn.parameters)}){mods}"
            )

        lines.append("")
        lines.append("--- Events ---")
        for ev in profile.events:
            lines.append(f"  {ev}")

        lines.append("")
        lines.append("--- Modifiers ---")
        for mod in profile.modifiers:
            lines.append(f"  {mod}")

        lines.append("")
        lines.append("--- External Dependencies ---")
        for dep in profile.external_dependencies:
            lines.append(f"  {dep}")

        lines.append("")
        lines.append("--- Imports ---")
        for imp in profile.imported_contracts:
            lines.append(f"  {imp}")

        return "\n".join(lines)
