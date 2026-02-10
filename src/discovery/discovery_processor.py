"""
Discovery Processor - 0-day vulnerability prompt/guide generation.

Follows the exact same pattern as BuildProcessor:
  - BaseProcessor.run() walks directories, calls _parse_file + _process per file
  - _parse_file reads a FORGE JSON, resolves project_path → .sol source code
  - _process chains all stages with progressive export after each

Input: FORGE JSON files (dataset/results/) — same output the forge pipeline produces
Output: DiscoveryReport JSON with prompts, guides, and investigation roadmaps

Usage (mirrors the original forge command):
  python main.py discover -t dataset/results/ -o discovery_output/
  python main.py discover -t dataset/results/project.pdf.json -o discovery_output/
"""

import os
import json
import glob
import dataclasses
from typing import List, Dict, Optional, Tuple
from loguru import logger
from pydantic import BaseModel

from core.models import DiscoveryReport, ContractProfile
from core.base import BaseProcessor
from core.invoker import CONFIG, CHUNK_LENGTH

from discovery.contract_analyzer import ContractAnalyzer
from discovery.vulnerability_hypothesizer import VulnerabilityHypothesizer
from discovery.prompt_generator import PromptGenerator
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
      _parse_file(filepath) → reads one FORGE JSON, returns resolved data
      _process(input) → chains all discovery stages, progressive export

    BaseProcessor.run() handles directory walking, history, and file validation.
    """

    def _initialize(self) -> bool:
        """
        Same pattern as BuildProcessor._initialize and ExtractProcessor._initialize:
        set valid_ext from config so BaseProcessor.run() knows which files to process.
        Also pre-build the dataset knowledge index (once, shared across all files).
        """
        self.valid_ext = [".json", ".sol", ".pdf", ".md", ".txt"]
        self.overwrite = True

        # Ensure output and log dirs exist
        os.makedirs(self.output, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

        # Build the dataset knowledge index once — same data the original
        # system already produced, now used as knowledge base
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
        Same pattern as BuildProcessor._parse_file:
        reads one input file, returns data for _process().

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

    def _process(self, input_data: dict) -> Optional[DiscoveryReport]:
        """
        Main pipeline — mirrors BuildProcessor._process pattern:
        chain stages sequentially, progressive export after each.

        Stages:
          1. Contract decomposition
          2. Attack surface mapping + hypothesis generation
          3. Discovery prompt synthesis
          4. Report assembly
        """
        source_files = input_data.get("source_files", [])
        findings_context = input_data.get("findings_context", [])

        if not source_files:
            return None

        analyzer = ContractAnalyzer()

        # ── Stage 1: Structural decomposition ──
        logger.info("STAGE 1/4: Structural decomposition ({} files)", len(source_files))
        all_profiles = []
        all_decompositions = []
        combined_source = ""
        primary_protocol_type = "unknown"

        for filepath, source_code in source_files:
            profile, decomposition = analyzer.analyze_file(filepath)
            all_profiles.append(profile)
            all_decompositions.append(decomposition)
            combined_source += f"\n// === {os.path.basename(filepath)} ===\n{source_code}\n"
            if profile.protocol_type != "unknown":
                primary_protocol_type = profile.protocol_type

        # The LLM decomposition IS the reasoning — it carries the investigator's
        # understanding from Phase 1. The static profile supplements it.
        combined_decomposition = "\n\n---\n\n".join(
            d for d in all_decompositions if d
        )
        combined_profile_text = "\n\n---\n\n".join(
            analyzer.profile_to_context(p) for p in all_profiles
        )

        # Enrich with existing findings from FORGE JSON
        if findings_context:
            combined_decomposition += "\n\n=== KNOWN FINDINGS FROM AUDIT ===\n"
            for f in findings_context[:30]:
                combined_decomposition += (
                    f"- [{f.get('severity','?')}] {f.get('title','')}: "
                    f"{f.get('description','')[:300]}\n"
                )

        profile_dicts = []
        for p in all_profiles:
            pd = dataclasses.asdict(p)
            pd.pop("raw_source", None)
            profile_dicts.append(pd)

        # Progressive export after stage 1
        partial_report = DiscoveryReport(
            target_path=self.filepath,
            contract_profiles=profile_dicts,
        )
        self.export_result(partial_report, filename=self.file_name, output_dir=self.output, overwrite=True)

        logger.info("Protocol type: {}. Decomposition complete.", primary_protocol_type)

        # ── Stage 2: Attack surfaces + hypotheses ──
        logger.info("STAGE 2/4: Attack surface mapping & hypothesis generation")

        # Use the full dataset index instead of random sampling
        dataset_context = self._dataset_index.get_context_for_protocol(primary_protocol_type)

        hypothesizer = VulnerabilityHypothesizer(dataset_path="")
        hyp_result = hypothesizer.generate_hypotheses(
            contract_profile_text=combined_profile_text,
            decomposition_raw=combined_decomposition,
            protocol_type=primary_protocol_type,
            source_code=combined_source,
            known_vulns_override=dataset_context,
        )

        attack_surfaces = hyp_result.get("attack_surfaces", "")
        hypotheses = hyp_result.get("hypotheses", "")
        known_vulns_context = hyp_result.get("known_vulns_context", "")

        # Progressive export after stage 2
        partial_report.attack_surfaces = self._safe_parse_list(attack_surfaces)
        partial_report.vulnerability_hypotheses = self._safe_parse_list(hypotheses)
        partial_report.meta_analysis = known_vulns_context
        self.export_result(partial_report, filename=self.file_name, output_dir=self.output, overwrite=True)

        logger.info("Attack surfaces mapped. Hypotheses generated.")

        # ── Stage 3: Prompt synthesis ──
        logger.info("STAGE 3/4: Discovery prompt synthesis")

        generator = PromptGenerator()
        prompts_result = generator.generate(
            contract_profile_text=combined_profile_text,
            attack_surfaces=attack_surfaces,
            hypotheses=hypotheses,
            protocol_type=primary_protocol_type,
            source_code=combined_source,
        )

        # ── Stage 4: Final report ──
        logger.info("STAGE 4/4: Report assembly")

        report = generator.build_report(
            target_path=self.filepath,
            contract_profiles=profile_dicts,
            attack_surfaces_raw=attack_surfaces,
            hypotheses_raw=hypotheses,
            prompts_result=prompts_result,
            known_vulns_context=known_vulns_context,
        )

        # Final export
        self.export_result(report, filename=self.file_name, output_dir=self.output, overwrite=True)

        logger.info(
            "Done: {} prompts, {} hypotheses",
            len(report.discovery_prompts),
            len(report.vulnerability_hypotheses),
        )
        return report

    @staticmethod
    def _safe_parse_list(raw: str) -> List[Dict]:
        """Parse raw LLM output into a list of dicts."""
        if not raw:
            return []
        import re
        pattern = re.compile(r"```(?:json\s+)?([\[{].*?[\]}])```", re.DOTALL)
        match = pattern.search(raw)
        if match:
            try:
                parsed = json.loads(match.group(1))
                if isinstance(parsed, list):
                    return parsed
                if isinstance(parsed, dict):
                    for v in parsed.values():
                        if isinstance(v, list):
                            return v
                    return [parsed]
            except Exception:
                pass
        return [{"raw_analysis": raw}]
