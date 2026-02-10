"""
Dataset Index - Builds structured knowledge from the FORGE dataset corpus.

Instead of randomly sampling findings, this module indexes the full 27k+
findings by CWE category and protocol type, providing rich real-world
grounding for the hypothesis generation stage.

Follows the original FORGE pattern: data is already local in dataset/,
just read and index it. No user intervention needed.
"""

import os
import json
import glob
import tiktoken
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from loguru import logger


class DatasetIndex:
    """
    Indexes the full FORGE dataset for use by the discovery pipeline.
    Builds structured knowledge maps from 27k+ real-world findings.
    """

    def __init__(self, results_path: str):
        self.results_path = results_path
        # CWE → list of (title, description, severity, location)
        self.by_cwe: Dict[str, List[dict]] = defaultdict(list)
        # severity → list of findings
        self.by_severity: Dict[str, List[dict]] = defaultdict(list)
        # Track protocol types seen in project paths
        self.total_findings = 0
        self.total_reports = 0
        self._indexed = False

    def build(self) -> bool:
        """
        Scan the full dataset/results/ directory and index all findings.
        Called once, results cached in memory for the session.
        """
        if self._indexed:
            return True

        if not self.results_path or not os.path.isdir(self.results_path):
            logger.warning("Dataset path not available: {}", self.results_path)
            return False

        json_files = glob.glob(os.path.join(self.results_path, "*.json"))
        if not json_files:
            logger.warning("No JSON files in {}", self.results_path)
            return False

        logger.info("Indexing {} dataset reports...", len(json_files))

        for fpath in json_files:
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue

            self.total_reports += 1
            findings = data.get("findings", [])

            for finding in findings:
                title = finding.get("title", "")
                desc = finding.get("description", "")
                severity = finding.get("severity", "").lower()
                location = finding.get("location", "")
                category = finding.get("category", {})

                if not title or title == "n/a":
                    continue

                entry = {
                    "title": title,
                    "description": desc[:500],
                    "severity": severity,
                    "location": location,
                }

                self.total_findings += 1

                # Index by severity
                if severity in ("critical", "high", "medium", "low"):
                    self.by_severity[severity].append(entry)

                # Index by every CWE in the category hierarchy
                for _level, cwes in category.items():
                    if isinstance(cwes, list):
                        for cwe in cwes:
                            self.by_cwe[cwe].append(entry)
                    elif isinstance(cwes, str):
                        self.by_cwe[cwes].append(entry)

        self._indexed = True
        logger.info(
            "Dataset indexed: {} reports, {} findings, {} CWE categories",
            self.total_reports, self.total_findings, len(self.by_cwe),
        )
        return True

    def get_context_for_protocol(self, protocol_type: str, max_tokens: int = 6000) -> str:
        """
        Build a rich context string for a specific protocol type.
        Prioritizes critical/high findings and CWEs most relevant to the protocol type.
        """
        if not self._indexed:
            self.build()

        # CWEs most relevant to each protocol type (based on real audit patterns)
        protocol_cwe_relevance = {
            "lending": [
                "CWE-682", "CWE-284", "CWE-269", "CWE-20", "CWE-691",
                "CWE-664", "CWE-693", "CWE-362", "CWE-754", "CWE-400",
            ],
            "dex_amm": [
                "CWE-682", "CWE-284", "CWE-691", "CWE-20", "CWE-362",
                "CWE-693", "CWE-664", "CWE-400", "CWE-754", "CWE-435",
            ],
            "yield_aggregator": [
                "CWE-682", "CWE-284", "CWE-269", "CWE-664", "CWE-691",
                "CWE-693", "CWE-20", "CWE-400", "CWE-754", "CWE-362",
            ],
            "staking": [
                "CWE-682", "CWE-284", "CWE-269", "CWE-691", "CWE-664",
                "CWE-20", "CWE-693", "CWE-754", "CWE-400", "CWE-362",
            ],
            "bridge": [
                "CWE-284", "CWE-693", "CWE-20", "CWE-269", "CWE-345",
                "CWE-362", "CWE-691", "CWE-664", "CWE-682", "CWE-435",
            ],
            "governance": [
                "CWE-284", "CWE-269", "CWE-362", "CWE-691", "CWE-682",
                "CWE-693", "CWE-664", "CWE-20", "CWE-754", "CWE-400",
            ],
            "token": [
                "CWE-710", "CWE-284", "CWE-682", "CWE-1041", "CWE-269",
                "CWE-691", "CWE-664", "CWE-20", "CWE-693", "CWE-400",
            ],
        }

        relevant_cwes = protocol_cwe_relevance.get(
            protocol_type,
            list(self.by_cwe.keys())[:15],
        )

        enc = tiktoken.get_encoding("cl100k_base")
        lines = [
            f"=== REAL-WORLD VULNERABILITY CORPUS ({self.total_findings} findings from {self.total_reports} audits) ===",
            f"Protocol type focus: {protocol_type}",
            "",
        ]

        # Section 1: Critical/High severity findings (most impactful)
        lines.append("--- CRITICAL & HIGH SEVERITY FINDINGS (from real audits) ---")
        token_count = len(enc.encode("\n".join(lines)))
        budget = max_tokens

        for severity in ("critical", "high"):
            entries = self.by_severity.get(severity, [])
            for entry in entries[:50]:
                line = f"[{severity.upper()}] {entry['title']}: {entry['description'][:200]}"
                line_tokens = len(enc.encode(line))
                if token_count + line_tokens > budget * 0.5:
                    break
                lines.append(line)
                token_count += line_tokens

        # Section 2: Findings by relevant CWE categories
        lines.append("")
        lines.append(f"--- FINDINGS BY CWE (most relevant to {protocol_type}) ---")

        for cwe in relevant_cwes:
            entries = self.by_cwe.get(cwe, [])
            if not entries:
                continue
            # Prioritize high-severity
            sorted_entries = sorted(
                entries,
                key=lambda e: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                    e.get("severity", ""), 4
                ),
            )
            lines.append(f"\n{cwe} ({len(entries)} findings):")
            for entry in sorted_entries[:8]:
                line = f"  [{entry['severity']}] {entry['title']}: {entry['description'][:150]}"
                line_tokens = len(enc.encode(line))
                if token_count + line_tokens > budget:
                    break
                lines.append(line)
                token_count += line_tokens

            if token_count > budget:
                break

        # Section 3: Statistical summary
        lines.append("")
        lines.append("--- DATASET STATISTICS ---")
        top_cwes = sorted(self.by_cwe.items(), key=lambda x: len(x[1]), reverse=True)[:20]
        lines.append("Top 20 CWE categories by frequency:")
        for cwe, entries in top_cwes:
            lines.append(f"  {cwe}: {len(entries)} findings")

        severity_counts = {s: len(entries) for s, entries in self.by_severity.items()}
        lines.append(f"By severity: {severity_counts}")

        return "\n".join(lines)

    def get_cwe_findings(self, cwe_id: str, limit: int = 20) -> List[dict]:
        """Get findings for a specific CWE."""
        if not self._indexed:
            self.build()
        return self.by_cwe.get(cwe_id, [])[:limit]

    def get_high_impact_findings(self, limit: int = 100) -> List[dict]:
        """Get the most impactful findings across the dataset."""
        if not self._indexed:
            self.build()
        results = []
        for severity in ("critical", "high"):
            results.extend(self.by_severity.get(severity, []))
        return results[:limit]
