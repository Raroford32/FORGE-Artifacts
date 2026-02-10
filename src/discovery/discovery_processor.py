"""
Discovery Processor - Main pipeline orchestrator for 0-day vulnerability
prompt and guideline generation.

Pipeline stages:
1. Contract Analysis (structural decomposition)
2. Attack Surface Mapping
3. Known Vulnerability Correlation
4. Novel Hypothesis Generation
5. Discovery Prompt Synthesis
6. Report Generation

Input: Solidity source files (file or directory)
Output: DiscoveryReport JSON with prompts, guides, and investigation roadmaps
"""

import os
import json
import dataclasses
from typing import List, Union
from loguru import logger
from pydantic import BaseModel

from core.models import DiscoveryReport, ContractProfile
from core.base import BaseProcessor
from core.invoker import CONFIG

from discovery.contract_analyzer import ContractAnalyzer
from discovery.vulnerability_hypothesizer import VulnerabilityHypothesizer
from discovery.prompt_generator import PromptGenerator


class DiscoveryProcessor(BaseProcessor):
    """
    Orchestrates the complete 0-day discovery pipeline.

    Takes Solidity source code as input and produces a DiscoveryReport
    containing structured prompts and investigation guides for finding
    novel vulnerabilities.
    """

    def _process(self, input_data: dict) -> DiscoveryReport:
        """
        Main processing pipeline.

        input_data is a dict with:
          - source_files: List of (filepath, source_code) tuples
        """
        source_files = input_data.get("source_files", [])
        if not source_files:
            logger.error("No source files to process")
            return DiscoveryReport()

        discovery_config = CONFIG.get("discovery", {})
        dataset_path = discovery_config.get("dataset_path", "")
        analysis_depth = discovery_config.get("analysis_depth", "comprehensive")

        # ── Stage 1: Contract Analysis ──
        logger.info("=" * 60)
        logger.info("STAGE 1: Contract Structural Decomposition")
        logger.info("=" * 60)

        analyzer = ContractAnalyzer()
        all_profiles = []
        all_decompositions = []
        combined_source = ""
        primary_protocol_type = "unknown"

        for filepath, source_code in source_files:
            logger.info("Analyzing: {}", filepath)
            profile, decomposition = analyzer.analyze_file(filepath)
            all_profiles.append(profile)
            all_decompositions.append(decomposition)
            combined_source += f"\n// === {filepath} ===\n{source_code}\n"

            # Track the dominant protocol type
            if profile.protocol_type != "unknown":
                primary_protocol_type = profile.protocol_type

        # Build combined profile text for downstream stages
        combined_profile_text = "\n\n---\n\n".join(
            analyzer.profile_to_context(p) for p in all_profiles
        )
        combined_decomposition = "\n\n---\n\n".join(
            d for d in all_decompositions if d
        )

        logger.info(
            "Decomposition complete. {} contracts analyzed. Protocol type: {}",
            len(all_profiles),
            primary_protocol_type,
        )

        # ── Stage 2 + 3: Attack Surface Mapping + Hypothesis Generation ──
        logger.info("=" * 60)
        logger.info("STAGE 2-3: Attack Surface Mapping & Hypothesis Generation")
        logger.info("=" * 60)

        hypothesizer = VulnerabilityHypothesizer(dataset_path=dataset_path)
        hyp_result = hypothesizer.generate_hypotheses(
            contract_profile_text=combined_profile_text,
            decomposition_raw=combined_decomposition,
            protocol_type=primary_protocol_type,
            source_code=combined_source,
        )

        attack_surfaces = hyp_result.get("attack_surfaces", "")
        hypotheses = hyp_result.get("hypotheses", "")
        known_vulns_context = hyp_result.get("known_vulns_context", "")

        logger.info("Attack surfaces mapped. Hypotheses generated.")

        # ── Stage 4: Discovery Prompt Synthesis ──
        logger.info("=" * 60)
        logger.info("STAGE 4: Discovery Prompt & Guide Synthesis")
        logger.info("=" * 60)

        generator = PromptGenerator()
        prompts_result = generator.generate(
            contract_profile_text=combined_profile_text,
            attack_surfaces=attack_surfaces,
            hypotheses=hypotheses,
            protocol_type=primary_protocol_type,
            source_code=combined_source,
        )

        logger.info(
            "Generated {} discovery prompts",
            len(prompts_result.get("discovery_prompts", [])),
        )

        # ── Stage 5: Report Assembly ──
        logger.info("=" * 60)
        logger.info("STAGE 5: Report Assembly")
        logger.info("=" * 60)

        # Convert profiles to serializable dicts
        profile_dicts = []
        for p in all_profiles:
            pd = dataclasses.asdict(p)
            # Remove raw source from the report to keep it manageable
            pd.pop("raw_source", None)
            profile_dicts.append(pd)

        report = generator.build_report(
            target_path=self.target,
            contract_profiles=profile_dicts,
            attack_surfaces_raw=attack_surfaces,
            hypotheses_raw=hypotheses,
            prompts_result=prompts_result,
            known_vulns_context=known_vulns_context,
        )

        logger.info("Discovery report assembled successfully.")
        return report

    def _parse_file(self, filepath: str) -> dict:
        """
        Parse input files. For the discovery pipeline, input is Solidity
        source code files (.sol).
        """
        self.filepath = filepath
        source_files = []

        if filepath.endswith(".sol"):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    source_code = f.read()
                source_files.append((filepath, source_code))
            except Exception as e:
                logger.error("Failed to read {}: {}", filepath, e)
        elif filepath.endswith(".json"):
            # Support processing JSON output from fetch stage
            # (contains project_path pointing to Solidity files)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                project_info = data.get("project_info", {})
                project_path = project_info.get("project_path", {})
                if isinstance(project_path, dict):
                    for name, path in project_path.items():
                        if os.path.isdir(path):
                            for root, _dirs, files in os.walk(path):
                                for fn in sorted(files):
                                    if fn.endswith(".sol"):
                                        fp = os.path.join(root, fn)
                                        try:
                                            with open(fp, "r", encoding="utf-8") as sf:
                                                source_files.append((fp, sf.read()))
                                        except Exception as e:
                                            logger.error("Failed to read {}: {}", fp, e)
            except Exception as e:
                logger.error("Failed to parse JSON {}: {}", filepath, e)

        return {"source_files": source_files}

    def _initialize(self) -> bool:
        """Initialize the discovery processor."""
        self.valid_ext = [".sol", ".json"]
        self.overwrite = True

        # Ensure output directory exists
        os.makedirs(self.output, exist_ok=True)

        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)

        return True

    def run(self) -> bool:
        """
        Override run to handle both single files and directories of
        Solidity contracts as a unified analysis target.
        """
        if not self._initialize():
            logger.error("Failed to initialize!")
            return False

        if not self.validate_target():
            logger.error("Invalid path or file!")
            return False

        if self.isdir:
            # For directories: collect all .sol files and process as one batch
            source_files = []
            for root, _dirs, files in os.walk(self.target):
                for f in sorted(files):
                    if f.endswith(".sol"):
                        filepath = os.path.join(root, f)
                        try:
                            with open(filepath, "r", encoding="utf-8") as sf:
                                source_files.append((filepath, sf.read()))
                        except Exception as e:
                            logger.error("Failed to read {}: {}", filepath, e)

            if not source_files:
                logger.error("No .sol files found in {}", self.target)
                return False

            logger.info("Found {} Solidity files to analyze", len(source_files))
            input_data = {"source_files": source_files}
            result = self._process(input_data)

            if result:
                dirname = os.path.basename(self.target.rstrip("/"))
                self.file_name = f"{dirname}_discovery"
                self.export_result(
                    result=result,
                    filename=self.file_name,
                    output_dir=self.output,
                    overwrite=True,
                )
                self._save_history(self.target, self.log_dir, is_failed=False)
                return True
            else:
                self._save_history(self.target, self.log_dir, is_failed=True)
                return False
        else:
            # Single file
            self.file_name = os.path.basename(self.target)
            input_data = self._parse_file(self.target)
            result = self._process(input_data)

            if result:
                self.export_result(
                    result=result,
                    filename=f"{self.file_name}_discovery",
                    output_dir=self.output,
                    overwrite=True,
                )
                self._save_history(self.target, self.log_dir, is_failed=False)
                return True
            else:
                self._save_history(self.target, self.log_dir, is_failed=True)
                return False
