"""
Discovery Processor — Adaptive investigation guidebook generation.

Follows the BaseProcessor contract:
  - BaseProcessor.run() walks directories, calls _parse_file + _process per file
  - _parse_file reads a FORGE JSON, resolves project_path → .sol source code
  - _process runs the Adaptive Investigation Engine:
      Understand → Generate → Evaluate → Refine → (loop) → Guidebook

Input: FORGE JSON files (dataset/results/), .sol files, or audit docs
Output: InvestigationGuidebook JSON — self-validated investigation methodology

Usage:
  python main.py discover                              # auto-detect dataset
  python main.py discover -t path/to/contract.sol      # single contract
  python main.py discover -t dataset/results/           # full dataset
"""

import os
import json
import glob
import dataclasses
from typing import List, Dict, Optional, Tuple
from loguru import logger
from pydantic import BaseModel

from core.models import InvestigationGuidebook, ContractProfile
from core.base import BaseProcessor
from core.invoker import CONFIG, CHUNK_LENGTH

from discovery.contract_analyzer import ContractAnalyzer
from discovery.agents import AdaptiveEngine
from discovery.dataset_index import DatasetIndex


def _auto_detect_dataset_path() -> str:
    """
    Auto-detect the FORGE dataset results path.
    Probes known locations relative to the source tree — same as how
    the original system expects the dataset to just be there.
    """
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dataset", "results"),
        os.path.join(os.getcwd(), "dataset", "results"),
        os.path.join(os.getcwd(), "..", "dataset", "results"),
    ]
    for path in candidates:
        path = os.path.normpath(path)
        if os.path.isdir(path):
            count = len(glob.glob(os.path.join(path, "*.json")))
            if count > 0:
                logger.info("Auto-detected dataset: {} ({} reports)", path, count)
                return path
    return ""


def _resolve_sol_from_project_path(project_path, base_dirs: List[str]) -> List[Tuple[str, str]]:
    """
    Resolve project_path from a FORGE JSON to actual .sol file contents.
    Tries each base_dir until the path resolves, exactly like how
    the fetcher writes paths relative to the output directory.
    """
    source_files = []

    if not project_path or project_path == "n/a":
        return source_files

    if isinstance(project_path, str) and project_path != "n/a":
        project_path = {"default": project_path}

    if not isinstance(project_path, dict):
        return source_files

    for _contract_name, path_val in project_path.items():
        if not path_val or path_val == "n/a":
            continue

        resolved = None
        for base in base_dirs:
            candidate = os.path.normpath(os.path.join(base, path_val)) if base else path_val
            if os.path.isdir(candidate):
                resolved = candidate
                break
            if os.path.isfile(candidate) and candidate.endswith(".sol"):
                resolved = candidate
                break

        if not resolved:
            continue

        if os.path.isfile(resolved):
            try:
                with open(resolved, "r", encoding="utf-8") as f:
                    source_files.append((resolved, f.read()))
            except Exception as e:
                logger.error("Failed to read {}: {}", resolved, e)
        elif os.path.isdir(resolved):
            for root, _dirs, files in os.walk(resolved):
                for fn in sorted(files):
                    if fn.endswith(".sol"):
                        fp = os.path.join(root, fn)
                        try:
                            with open(fp, "r", encoding="utf-8") as f:
                                source_files.append((fp, f.read()))
                        except Exception as e:
                            logger.error("Failed to read {}: {}", fp, e)

    return source_files


class DiscoveryProcessor(BaseProcessor):
    """
    Follows the exact BaseProcessor contract:
      _initialize() → sets valid_ext, loads dataset index
      _parse_file(filepath) → reads one input file, returns resolved data
      _process(input) → runs Adaptive Investigation Engine

    BaseProcessor.run() handles directory walking, history, and file validation.
    """

    def _initialize(self) -> bool:
        """
        Same pattern as BuildProcessor._initialize:
        set valid_ext from config so BaseProcessor.run() knows which files to process.
        Also pre-build the dataset knowledge index (once, shared across all files).
        """
        self.valid_ext = [".json", ".sol", ".pdf", ".md", ".txt"]
        self.overwrite = True

        # Ensure output and log dirs exist
        os.makedirs(self.output, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

        # Build the dataset knowledge index once
        dataset_path = CONFIG.get("discovery", {}).get("dataset_path", "")
        if not dataset_path:
            dataset_path = _auto_detect_dataset_path()

        self._dataset_index = DatasetIndex(dataset_path)
        self._dataset_index.build()

        # Precompute base directories for resolving project_path
        src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._base_dirs = [
            "",                                         # absolute paths
            os.path.join(src_dir, "..", "dataset"),      # dataset/contracts/...
            os.path.join(src_dir, ".."),                 # repo root
            os.getcwd(),                                 # cwd
            src_dir,                                     # src/
        ]

        return True

    def _parse_file(self, filepath: str) -> Optional[dict]:
        """
        Reads one input file, returns data for _process().

        For FORGE JSONs: resolves project_path to .sol source code.
        For .sol files: reads directly.
        For audit docs: chains extract → fetch first.
        """
        self.filepath = filepath

        if filepath.endswith(".json"):
            return self._parse_forge_json(filepath)
        elif filepath.endswith(".sol"):
            return self._parse_sol_file(filepath)
        else:
            return self._parse_audit_doc(filepath)

    def _parse_forge_json(self, filepath: str) -> Optional[dict]:
        """Read a FORGE JSON and resolve its project_path to source files."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error("Failed to read {}: {}", filepath, e)
            return None

        project_info = data.get("project_info", {})
        project_path = project_info.get("project_path", {})

        # Add the JSON file's own directory to resolution bases
        json_dir = os.path.dirname(os.path.abspath(filepath))
        base_dirs = [json_dir] + self._base_dirs

        source_files = _resolve_sol_from_project_path(project_path, base_dirs)

        if not source_files:
            logger.warning("No .sol files resolved from {}", filepath)
            return None

        return {
            "source_files": source_files,
            "findings_context": data.get("findings", []),
            "project_info": project_info,
        }

    def _parse_sol_file(self, filepath: str) -> Optional[dict]:
        """Read a single .sol file directly."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()
            return {
                "source_files": [(filepath, source)],
                "findings_context": [],
                "project_info": {},
            }
        except Exception as e:
            logger.error("Failed to read {}: {}", filepath, e)
            return None

    def _parse_audit_doc(self, filepath: str) -> Optional[dict]:
        """
        Full pipeline: extract → fetch → resolve.
        Same chaining as BuildProcessor._process but only the
        extract+fetch stages.
        """
        from extractor.document_handler import DocumentHandler
        from extractor.map_reducer import MapReducer
        from fetcher.fetch_processor import _fetcher
        from core.models import Report

        logger.info("Full pipeline from audit doc: {}", filepath)

        max_heading_level = CONFIG.get("extractor", {}).get("max_heading_level", 3)
        doc_handler = DocumentHandler(
            max_level=max_heading_level, max_tokens=CHUNK_LENGTH
        )
        documents = doc_handler.process(filepath=filepath)
        if not documents:
            logger.error("No content from {}", filepath)
            return None

        map_reducer = MapReducer()
        mr_result = map_reducer.map_reduce(documents, CHUNK_LENGTH)
        logger.info("Extracted {} findings", len(mr_result.findings))

        report = Report(
            path=filepath,
            project_info=mr_result.project_info,
            findings=mr_result.findings,
        )

        if not report.project_info.is_empty():
            logger.info("Fetching source code...")
            try:
                report.project_info = _fetcher(report, self.output)
            except Exception as e:
                logger.error("Fetch failed: {}", e)

        project_path = report.project_info.project_path
        source_files = _resolve_sol_from_project_path(project_path, self._base_dirs)

        findings_context = [
            {"title": f.title, "description": f.description, "severity": f.severity}
            for f in mr_result.findings
        ]

        if not source_files:
            logger.warning("No .sol files after extract+fetch for {}", filepath)
            return None

        return {
            "source_files": source_files,
            "findings_context": findings_context,
            "project_info": dataclasses.asdict(report.project_info),
        }

    def _process(self, input_data: dict) -> Optional[InvestigationGuidebook]:
        """
        Run the Adaptive Investigation Engine.

        The engine handles everything internally:
          Understand → Generate → Evaluate → Refine → (loop) → Guidebook

        No fixed stages. The engine adapts depth and focus based on
        what it discovers in the source code.
        """
        source_files = input_data.get("source_files", [])
        findings_context = input_data.get("findings_context", [])

        if not source_files:
            return None

        # Combine source files
        combined_source = ""
        primary_protocol_type = "unknown"

        analyzer = ContractAnalyzer()
        for filepath, source_code in source_files:
            combined_source += f"\n// === {os.path.basename(filepath)} ===\n{source_code}\n"
            # Quick protocol type detection (static, no LLM needed)
            detected = analyzer._classify_protocol_type(source_code)
            if detected != "unknown":
                primary_protocol_type = detected

        logger.info(
            "Processing {} source files ({} chars), protocol type: {}",
            len(source_files), len(combined_source), primary_protocol_type,
        )

        # Get dataset grounding context
        dataset_context = self._dataset_index.get_context_for_protocol(primary_protocol_type)

        # Build and run the adaptive engine
        engine = AdaptiveEngine(
            max_iterations=CONFIG.get("discovery", {}).get("max_iterations", 3),
            quality_threshold=CONFIG.get("discovery", {}).get("quality_threshold", 0.7),
        )

        def _export_progressive(guidebook: InvestigationGuidebook):
            """Progressive export callback — saves partial results to disk."""
            self.export_result(
                guidebook,
                filename=self.file_name,
                output_dir=self.output,
                overwrite=True,
            )

        guidebook = engine.run(
            source_code=combined_source,
            dataset_context=dataset_context,
            findings_context=findings_context,
            protocol_type=primary_protocol_type,
            target_path=self.filepath,
            export_callback=_export_progressive,
        )

        # Final export
        self.export_result(
            guidebook,
            filename=self.file_name,
            output_dir=self.output,
            overwrite=True,
        )

        logger.info(
            "Done: {} prompts, {} guides, quality={:.2f}, {} iterations",
            len(guidebook.investigation_prompts),
            len(guidebook.reasoning_guides),
            guidebook.final_quality_score,
            guidebook.iterations_to_converge,
        )

        return guidebook
