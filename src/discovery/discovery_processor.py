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

Input modes (all auto-detected):
  - Solidity source files (.sol) or directory of them
  - FORGE JSON output (contains project_path → auto-resolves to .sol files)
  - Directory of FORGE JSONs (batch mode over dataset/results/)
  - Full pipeline from audit documents (extract → fetch → discover)

Output: DiscoveryReport JSON with prompts, guides, and investigation roadmaps
"""

import os
import json
import glob
import dataclasses
from typing import List, Dict, Optional, Tuple
from loguru import logger
from pydantic import BaseModel

from core.models import DiscoveryReport, ContractProfile, Report
from core.base import BaseProcessor
from core.invoker import CONFIG, CHUNK_LENGTH

from discovery.contract_analyzer import ContractAnalyzer
from discovery.vulnerability_hypothesizer import VulnerabilityHypothesizer
from discovery.prompt_generator import PromptGenerator


def _auto_detect_dataset_path() -> str:
    """
    Auto-detect the FORGE dataset results path by probing known locations
    relative to the source tree. Returns path if found, empty string otherwise.
    """
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dataset", "results"),
        os.path.join(os.getcwd(), "dataset", "results"),
        os.path.join(os.getcwd(), "..", "dataset", "results"),
    ]
    for path in candidates:
        if os.path.isdir(path):
            count = len(glob.glob(os.path.join(path, "*.json")))
            if count > 0:
                logger.info("Auto-detected dataset at {} ({} reports)", path, count)
                return path
    return ""


def _resolve_sol_files_from_json(filepath: str) -> List[Tuple[str, str]]:
    """
    Given a FORGE JSON output file, resolve its project_path to actual
    Solidity source files. Handles both absolute and relative paths
    (relative to the dataset/contracts/ directory or the JSON's own directory).
    """
    source_files = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.error("Failed to read JSON {}: {}", filepath, e)
        return source_files

    project_info = data.get("project_info", {})
    project_path = project_info.get("project_path", {})

    if not project_path or project_path == "n/a":
        return source_files

    if isinstance(project_path, str) and project_path != "n/a":
        project_path = {"default": project_path}

    if not isinstance(project_path, dict):
        return source_files

    # Base directories to resolve relative paths against
    json_dir = os.path.dirname(os.path.abspath(filepath))
    src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_base = os.path.join(src_dir, "..", "dataset")
    cwd = os.getcwd()

    for _contract_name, path_val in project_path.items():
        if not path_val or path_val == "n/a":
            continue

        # Try resolving the path in multiple ways
        resolved = None
        for base in [
            "",                                     # absolute path
            json_dir,                               # relative to JSON file
            dataset_base,                           # relative to dataset/
            cwd,                                    # relative to cwd
            os.path.join(src_dir, ".."),            # relative to repo root
            src_dir,                                # relative to src/
        ]:
            candidate = os.path.join(base, path_val) if base else path_val
            candidate = os.path.normpath(candidate)
            if os.path.isdir(candidate):
                resolved = candidate
                break
            elif os.path.isfile(candidate) and candidate.endswith(".sol"):
                resolved = candidate
                break

        if not resolved:
            logger.debug("Could not resolve project_path '{}' from {}", path_val, filepath)
            continue

        if os.path.isfile(resolved):
            try:
                with open(resolved, "r", encoding="utf-8") as sf:
                    source_files.append((resolved, sf.read()))
            except Exception as e:
                logger.error("Failed to read {}: {}", resolved, e)
        elif os.path.isdir(resolved):
            for root, _dirs, files in os.walk(resolved):
                for fn in sorted(files):
                    if fn.endswith(".sol"):
                        fp = os.path.join(root, fn)
                        try:
                            with open(fp, "r", encoding="utf-8") as sf:
                                source_files.append((fp, sf.read()))
                        except Exception as e:
                            logger.error("Failed to read {}: {}", fp, e)

    return source_files


class DiscoveryProcessor(BaseProcessor):
    """
    Orchestrates the complete 0-day discovery pipeline.

    Accepts any input type the FORGE ecosystem produces and automatically
    resolves it to Solidity source code for analysis:

    - .sol file or directory → analyze directly
    - FORGE JSON → resolve project_path → analyze contracts
    - Directory of FORGE JSONs → batch process each project
    - Audit documents → run extract + fetch first, then analyze

    Requires only LLM API key to be configured. Everything else is
    auto-detected from the existing FORGE dataset and infrastructure.
    """

    def _process(self, input_data: dict) -> DiscoveryReport:
        """
        Main processing pipeline.

        input_data keys:
          - source_files: List of (filepath, source_code) tuples
          - findings_context: Optional list of known findings from FORGE JSON
          - project_name: Optional project name for the report
        """
        source_files = input_data.get("source_files", [])
        findings_context = input_data.get("findings_context", [])
        project_name = input_data.get("project_name", "")

        if not source_files:
            logger.error("No source files resolved — nothing to process")
            return DiscoveryReport()

        logger.info(
            "Processing {} source files for project '{}'",
            len(source_files), project_name or "(unnamed)"
        )

        discovery_config = CONFIG.get("discovery", {})

        # Auto-detect dataset path if not configured
        dataset_path = discovery_config.get("dataset_path", "")
        if not dataset_path:
            dataset_path = _auto_detect_dataset_path()

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
            combined_source += f"\n// === {os.path.basename(filepath)} ===\n{source_code}\n"

            if profile.protocol_type != "unknown":
                primary_protocol_type = profile.protocol_type

        combined_profile_text = "\n\n---\n\n".join(
            analyzer.profile_to_context(p) for p in all_profiles
        )
        combined_decomposition = "\n\n---\n\n".join(
            d for d in all_decompositions if d
        )

        # Enrich with existing findings context from FORGE JSON
        if findings_context:
            combined_profile_text += "\n\n=== KNOWN FINDINGS FROM AUDIT ===\n"
            for f in findings_context[:20]:
                combined_profile_text += (
                    f"- [{f.get('severity','?')}] {f.get('title','')}: "
                    f"{f.get('description','')[:300]}\n"
                )

        logger.info(
            "Decomposition complete. {} contracts analyzed. Protocol type: {}",
            len(all_profiles), primary_protocol_type,
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

        profile_dicts = []
        for p in all_profiles:
            pd = dataclasses.asdict(p)
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

        logger.info("Discovery report assembled.")
        return report

    def _collect_source_from_path(self, target: str) -> List[dict]:
        """
        Smart input resolver. Takes any path the FORGE ecosystem produces
        and returns a list of job dicts, each with:
          - source_files: List of (filepath, source_code) tuples
          - findings_context: List of dicts (from FORGE JSON findings)
          - project_name: str
        """
        jobs = []

        if os.path.isfile(target):
            if target.endswith(".sol"):
                jobs.append(self._job_from_sol_file(target))
            elif target.endswith(".json"):
                jobs.append(self._job_from_forge_json(target))
            else:
                # Try reading as audit doc through the extract+fetch pipeline
                jobs.append(self._job_from_audit_doc(target))
        elif os.path.isdir(target):
            # Check what's in the directory
            sol_files = glob.glob(os.path.join(target, "**", "*.sol"), recursive=True)
            json_files = glob.glob(os.path.join(target, "*.json"))

            if sol_files and not json_files:
                # Directory of .sol files → single job
                jobs.append(self._job_from_sol_directory(target))
            elif json_files:
                # Directory of FORGE JSONs → one job per JSON
                for jf in sorted(json_files):
                    job = self._job_from_forge_json(jf)
                    if job and job.get("source_files"):
                        jobs.append(job)
                    else:
                        logger.debug("No source files resolved from {}", jf)
            else:
                logger.error("No .sol or .json files found in {}", target)
        else:
            logger.error("Target does not exist: {}", target)

        return jobs

    def _job_from_sol_file(self, filepath: str) -> dict:
        """Create a job from a single .sol file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                source = f.read()
            return {
                "source_files": [(filepath, source)],
                "findings_context": [],
                "project_name": os.path.splitext(os.path.basename(filepath))[0],
            }
        except Exception as e:
            logger.error("Failed to read {}: {}", filepath, e)
            return {"source_files": [], "findings_context": [], "project_name": ""}

    def _job_from_sol_directory(self, dirpath: str) -> dict:
        """Create a job from a directory of .sol files."""
        source_files = []
        for root, _dirs, files in os.walk(dirpath):
            for fn in sorted(files):
                if fn.endswith(".sol"):
                    fp = os.path.join(root, fn)
                    try:
                        with open(fp, "r", encoding="utf-8") as f:
                            source_files.append((fp, f.read()))
                    except Exception as e:
                        logger.error("Failed to read {}: {}", fp, e)
        return {
            "source_files": source_files,
            "findings_context": [],
            "project_name": os.path.basename(dirpath.rstrip("/")),
        }

    def _job_from_forge_json(self, filepath: str) -> dict:
        """
        Create a job from a FORGE pipeline JSON output.
        Resolves project_path to .sol files and includes existing findings
        as enrichment context.
        """
        source_files = _resolve_sol_files_from_json(filepath)

        # Also extract findings for context enrichment
        findings_context = []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            findings_context = data.get("findings", [])
        except Exception:
            pass

        project_name = os.path.splitext(os.path.basename(filepath))[0]
        # Strip common suffixes
        for suffix in [".pdf", ".md", ".txt"]:
            if project_name.endswith(suffix):
                project_name = project_name[: -len(suffix)]

        return {
            "source_files": source_files,
            "findings_context": findings_context,
            "project_name": project_name,
        }

    def _job_from_audit_doc(self, filepath: str) -> dict:
        """
        Full pipeline: extract vulnerabilities from an audit document,
        fetch the source code, then create a discovery job from the result.

        This chains extract → fetch → discover in one shot.
        """
        from extractor.document_handler import DocumentHandler
        from extractor.map_reducer import MapReducer
        from fetcher.fetch_processor import _fetcher
        from core.models import Report as ForgeReport

        logger.info("Full pipeline: extracting from audit document {}", filepath)

        max_heading_level = CONFIG.get("extractor", {}).get("max_heading_level", 3)
        context_length = CHUNK_LENGTH

        # Stage A: Extract
        doc_handler = DocumentHandler(
            max_level=max_heading_level, max_tokens=context_length
        )
        documents = doc_handler.process(filepath=filepath)
        if not documents:
            logger.error("No content extracted from {}", filepath)
            return {"source_files": [], "findings_context": [], "project_name": ""}

        map_reducer = MapReducer()
        mr_result = map_reducer.map_reduce(documents, context_length)
        logger.info("Extracted {} findings", len(mr_result.findings))

        report = ForgeReport(
            path=filepath,
            project_info=mr_result.project_info,
            findings=mr_result.findings,
        )

        # Stage B: Fetch source code
        if not report.project_info.is_empty():
            logger.info("Fetching source code...")
            try:
                report.project_info = _fetcher(report, self.output)
            except Exception as e:
                logger.error("Fetch failed: {}", e)

        # Stage C: Resolve fetched source
        source_files = []
        project_path = report.project_info.project_path
        if isinstance(project_path, dict):
            for _name, path_val in project_path.items():
                if path_val and path_val != "n/a" and os.path.isdir(path_val):
                    for root, _dirs, files in os.walk(path_val):
                        for fn in sorted(files):
                            if fn.endswith(".sol"):
                                fp = os.path.join(root, fn)
                                try:
                                    with open(fp, "r", encoding="utf-8") as f:
                                        source_files.append((fp, f.read()))
                                except Exception as e:
                                    logger.error("Failed to read {}: {}", fp, e)

        findings_context = [
            {"title": f.title, "description": f.description, "severity": f.severity}
            for f in mr_result.findings
        ]

        project_name = os.path.splitext(os.path.basename(filepath))[0]
        return {
            "source_files": source_files,
            "findings_context": findings_context,
            "project_name": project_name,
        }

    def _parse_file(self, filepath: str) -> dict:
        """Parse a single input file into a job dict."""
        self.filepath = filepath
        if filepath.endswith(".sol"):
            return self._job_from_sol_file(filepath)
        elif filepath.endswith(".json"):
            return self._job_from_forge_json(filepath)
        else:
            return self._job_from_audit_doc(filepath)

    def _initialize(self) -> bool:
        """Initialize the discovery processor."""
        discovery_config = CONFIG.get("discovery", {})
        self.valid_ext = discovery_config.get(
            "valid_ext", [".sol", ".json", ".pdf", ".md", ".txt"]
        )
        self.overwrite = True
        os.makedirs(self.output, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        return True

    def run(self) -> bool:
        """
        Smart entry point that auto-detects input type and processes accordingly.

        Handles:
        - Single .sol file → analyze it
        - Single FORGE JSON → resolve source, analyze
        - Single audit doc (.pdf/.md) → extract → fetch → analyze
        - Directory of .sol → analyze as one project
        - Directory of FORGE JSONs → batch process each project
        - Mixed directory → process each file by type
        """
        if not self._initialize():
            logger.error("Failed to initialize!")
            return False

        if not os.path.exists(self.target):
            logger.error("Target does not exist: {}", self.target)
            return False

        # Collect all jobs from the target
        jobs = self._collect_source_from_path(self.target)

        if not jobs:
            logger.error("No processable input found at {}", self.target)
            return False

        logger.info("Collected {} job(s) to process", len(jobs))

        success_count = 0
        for i, job in enumerate(jobs):
            source_files = job.get("source_files", [])
            project_name = job.get("project_name", f"project_{i}")

            if not source_files:
                logger.warning("Job '{}' has no source files, skipping", project_name)
                continue

            # Skip if already processed
            job_key = f"{project_name}:{len(source_files)}files"
            if job_key in self.history.finished:
                logger.info("Skipping already processed: {}", project_name)
                continue

            logger.info(
                "Processing job {}/{}: '{}' ({} source files)",
                i + 1, len(jobs), project_name, len(source_files),
            )

            try:
                result = self._process(job)
                if result and result.discovery_prompts:
                    output_name = f"{project_name}_discovery"
                    self.export_result(
                        result=result,
                        filename=output_name,
                        output_dir=self.output,
                        overwrite=True,
                    )
                    self._save_history(job_key, self.log_dir, is_failed=False)
                    success_count += 1
                    logger.info(
                        "Completed '{}': {} prompts generated",
                        project_name,
                        len(result.discovery_prompts),
                    )
                else:
                    self._save_history(job_key, self.log_dir, is_failed=True)
                    logger.warning("Job '{}' produced no discovery prompts", project_name)
            except Exception as e:
                logger.error("Job '{}' failed: {}", project_name, e)
                self._save_history(job_key, self.log_dir, is_failed=True)

        logger.info(
            "Discovery complete: {}/{} jobs succeeded", success_count, len(jobs)
        )
        return success_count > 0
