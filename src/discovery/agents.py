"""
Adaptive Investigation Engine — Self-evolving vulnerability discovery.

This is the core engine that replaces the fixed 4-stage pipeline.
Instead of predefined stages, it runs an adaptive loop:

    Understand → Generate Methodology → Evaluate → Refine → (loop) → Guidebook

The engine:
  - Adapts depth based on protocol complexity
  - Self-evaluates its output using strict criteria
  - Refines methodology iteratively until quality threshold is met
  - Produces a self-validated investigation guidebook
  - Grounds everything in source code and dataset evidence

Architecture:
  AdaptiveEngine.run()
    ├── _understand()          — Build deep understanding from source code
    ├── _generate_methodology() — Produce investigation prompts + guides
    ├── _evaluate()            — Self-evaluate methodology quality
    ├── _refine()              — Improve based on evaluation gaps
    └── _synthesize_guidebook() — Produce final self-validated output

Every output is grounded in code. Agents do not create content from
themselves — they derive everything from source code and dataset evidence.
"""

import re
import json
import time
import hashlib
from typing import Dict, List, Optional, Callable
from loguru import logger
from pydantic import BaseModel

from core.models import InvestigationGuidebook, EvaluationResult
from core.invoker import (
    invoke_understand,
    invoke_generate_methodology,
    invoke_evaluate,
    invoke_refine,
    invoke_synthesize_guidebook,
    MAX_RETRIES,
    INTERVAL,
)
from vendor.commentjson import commentjson


class AdaptiveEngine(BaseModel):
    """
    Self-evolving investigation methodology engine.

    Runs an adaptive loop of understand → generate → evaluate → refine
    until the methodology meets quality standards, then synthesizes
    the final investigation guidebook.
    """

    max_iterations: int = 3
    quality_threshold: float = 0.7

    class Config:
        arbitrary_types_allowed = True

    def run(
        self,
        source_code: str,
        dataset_context: str,
        findings_context: List[Dict],
        protocol_type: str = "unknown",
        target_path: str = "",
        export_callback: Optional[Callable] = None,
    ) -> InvestigationGuidebook:
        """
        Run the full adaptive investigation engine.

        Args:
            source_code: Combined Solidity source code
            dataset_context: Pre-built context from DatasetIndex
            findings_context: Known findings from audit reports
            protocol_type: Auto-detected protocol type
            target_path: File path being analyzed
            export_callback: Optional callback for progressive export

        Returns:
            InvestigationGuidebook — self-validated investigation methodology
        """
        logger.info(
            "Adaptive Engine starting: {} chars source, protocol={}",
            len(source_code), protocol_type,
        )

        # Adapt depth to protocol complexity
        effective_max = self._compute_adaptive_depth(source_code)
        effective_max = min(effective_max, self.max_iterations)
        logger.info("Adaptive depth: {} iterations (max configured: {})",
                     effective_max, self.max_iterations)

        # Enrich source context with known findings
        enriched_context = dataset_context
        if findings_context:
            findings_text = "\n\n=== KNOWN AUDIT FINDINGS FOR THIS CONTRACT ===\n"
            for f in findings_context[:30]:
                findings_text += (
                    f"- [{f.get('severity','?')}] {f.get('title','')}: "
                    f"{f.get('description','')[:300]}\n"
                )
            enriched_context = findings_text + "\n" + dataset_context

        # ── Phase: Understand ──
        logger.info("UNDERSTAND: Building deep understanding of the contract...")
        understanding = self._understand(source_code, enriched_context)

        if not understanding:
            logger.error("Understanding phase produced no output")
            return self._empty_guidebook(target_path, protocol_type)

        # ── Phase: Generate initial methodology ──
        logger.info("GENERATE: Producing initial investigation methodology...")
        methodology = self._generate_methodology(
            understanding, source_code, enriched_context
        )

        if not methodology:
            logger.error("Methodology generation produced no output")
            return self._empty_guidebook(target_path, protocol_type)

        # Progressive export
        if export_callback:
            export_callback(self._build_partial_guidebook(
                target_path, protocol_type, source_code, understanding,
                methodology, [], 0, 0,
            ))

        # ── Iterative: Evaluate → Refine loop ──
        evaluation_history = []
        methodology_evolution = [methodology]

        for iteration in range(effective_max):
            iter_num = iteration + 1
            logger.info(
                "EVALUATE: Iteration {}/{} — judging methodology quality...",
                iter_num, effective_max,
            )

            # Evaluate
            evaluation = self._evaluate(
                methodology, source_code, enriched_context
            )

            eval_dict = self._parse_evaluation(evaluation, iter_num)
            evaluation_history.append(eval_dict)
            quality_score = eval_dict.get("quality_score", 0.0)

            logger.info(
                "Evaluation {}/{}: score={:.2f} (threshold={:.2f}), recommendation={}",
                iter_num, effective_max, quality_score,
                self.quality_threshold, eval_dict.get("recommendation", "?"),
            )

            # Progressive export after each evaluation
            if export_callback:
                export_callback(self._build_partial_guidebook(
                    target_path, protocol_type, source_code, understanding,
                    methodology, evaluation_history, quality_score, iter_num,
                ))

            # Check convergence
            if quality_score >= self.quality_threshold:
                logger.info(
                    "CONVERGED at iteration {} with score {:.2f}",
                    iter_num, quality_score,
                )
                break

            # Refine if not converged and not last iteration
            if iter_num < effective_max:
                logger.info(
                    "REFINE: Addressing {} coverage gaps, {} depth issues, {} grounding failures...",
                    len(eval_dict.get("coverage_gaps", [])),
                    len(eval_dict.get("depth_issues", [])),
                    len(eval_dict.get("grounding_failures", [])),
                )

                refined = self._refine(methodology, evaluation, source_code)

                if refined and len(refined) > len(methodology) * 0.5:
                    methodology = refined
                    methodology_evolution.append(methodology)
                    logger.info("Methodology refined ({} chars)", len(methodology))
                else:
                    logger.warning("Refinement produced insufficient output, keeping current methodology")

        # ── Final: Synthesize guidebook ──
        logger.info("SYNTHESIZE: Producing final investigation guidebook...")
        final_score = evaluation_history[-1].get("quality_score", 0.0) if evaluation_history else 0.0

        guidebook = self._synthesize_guidebook(
            methodology=methodology,
            understanding=understanding,
            evaluation_history=json.dumps(evaluation_history, indent=2),
            source_code=source_code,
            target_path=target_path,
            protocol_type=protocol_type,
            final_score=final_score,
            iterations=len(evaluation_history),
            methodology_evolution=methodology_evolution,
        )

        logger.info(
            "Guidebook complete: {} prompts, {} guides, score={:.2f}, {} iterations",
            len(guidebook.investigation_prompts),
            len(guidebook.reasoning_guides),
            guidebook.final_quality_score,
            guidebook.iterations_to_converge,
        )

        return guidebook

    # ── Core engine methods ──

    def _understand(self, source_code: str, dataset_context: str, prior_gaps: str = "") -> str:
        """Build deep understanding of the contract. Retry on failure."""
        retry = 0
        while retry < MAX_RETRIES:
            try:
                result = invoke_understand(source_code, dataset_context, prior_gaps)
                if result and len(result) > 200:
                    return result
                retry += 1
                logger.warning("Understanding insufficient, retry {}/{}", retry, MAX_RETRIES)
            except Exception as e:
                retry += 1
                backoff = INTERVAL * retry
                logger.error("Understanding error: {}, retry {}/{} after {}s", e, retry, MAX_RETRIES, backoff)
                if retry < MAX_RETRIES:
                    time.sleep(backoff)
        return ""

    def _generate_methodology(self, understanding: str, source_code: str, dataset_context: str) -> str:
        """Generate investigation methodology from understanding."""
        retry = 0
        while retry < MAX_RETRIES:
            try:
                result = invoke_generate_methodology(understanding, source_code, dataset_context)
                if result and len(result) > 200:
                    return result
                retry += 1
                logger.warning("Methodology generation insufficient, retry {}/{}", retry, MAX_RETRIES)
            except Exception as e:
                retry += 1
                backoff = INTERVAL * retry
                logger.error("Methodology error: {}, retry {}/{} after {}s", e, retry, MAX_RETRIES, backoff)
                if retry < MAX_RETRIES:
                    time.sleep(backoff)
        return ""

    def _evaluate(self, methodology: str, source_code: str, dataset_context: str) -> str:
        """Self-evaluate methodology quality."""
        retry = 0
        while retry < MAX_RETRIES:
            try:
                result = invoke_evaluate(methodology, source_code, dataset_context)
                if result and len(result) > 100:
                    return result
                retry += 1
                logger.warning("Evaluation insufficient, retry {}/{}", retry, MAX_RETRIES)
            except Exception as e:
                retry += 1
                backoff = INTERVAL * retry
                logger.error("Evaluation error: {}, retry {}/{} after {}s", e, retry, MAX_RETRIES, backoff)
                if retry < MAX_RETRIES:
                    time.sleep(backoff)
        # If evaluation fails, return a conservative "refine" response
        return json.dumps({
            "quality_score": 0.0,
            "recommendation": "refine",
            "coverage_gaps": ["Evaluation failed — full re-evaluation needed"],
            "refinement_targets": ["Re-evaluate from scratch"],
        })

    def _refine(self, methodology: str, evaluation: str, source_code: str) -> str:
        """Refine methodology based on evaluation feedback."""
        retry = 0
        while retry < MAX_RETRIES:
            try:
                result = invoke_refine(methodology, evaluation, source_code)
                if result and len(result) > 200:
                    return result
                retry += 1
                logger.warning("Refinement insufficient, retry {}/{}", retry, MAX_RETRIES)
            except Exception as e:
                retry += 1
                backoff = INTERVAL * retry
                logger.error("Refinement error: {}, retry {}/{} after {}s", e, retry, MAX_RETRIES, backoff)
                if retry < MAX_RETRIES:
                    time.sleep(backoff)
        return ""

    def _synthesize_guidebook(
        self,
        methodology: str,
        understanding: str,
        evaluation_history: str,
        source_code: str,
        target_path: str,
        protocol_type: str,
        final_score: float,
        iterations: int,
        methodology_evolution: List[str],
    ) -> InvestigationGuidebook:
        """Synthesize the final investigation guidebook."""
        # Call LLM for final synthesis
        raw_output = ""
        retry = 0
        while retry < MAX_RETRIES:
            try:
                raw_output = invoke_synthesize_guidebook(
                    methodology, understanding, evaluation_history, source_code,
                )
                if raw_output and len(raw_output) > 200:
                    break
                retry += 1
            except Exception as e:
                retry += 1
                backoff = INTERVAL * retry
                logger.error("Guidebook synthesis error: {}, retry {}/{}", e, retry, MAX_RETRIES)
                if retry < MAX_RETRIES:
                    time.sleep(backoff)

        # Parse the guidebook
        parsed = self._extract_json(raw_output) if raw_output else {}
        if not parsed:
            parsed = {}

        # Build the guidebook model
        guidebook = InvestigationGuidebook(
            target_path=target_path,
            protocol_type=protocol_type,
            investigation_prompts=parsed.get("investigation_prompts", self._extract_prompts_from_methodology(methodology)),
            reasoning_guides=parsed.get("reasoning_guides", []),
            evaluation_history=json.loads(evaluation_history) if isinstance(evaluation_history, str) else evaluation_history,
            final_quality_score=final_score,
            iterations_to_converge=iterations,
            source_code_hash=hashlib.sha256(source_code.encode()).hexdigest()[:16],
            dataset_findings_used=0,
            understanding=understanding[:5000],  # Truncate for storage
            methodology_evolution=[m[:2000] for m in methodology_evolution],
        )

        # Add roadmap and summary from parsed output
        if parsed.get("investigation_roadmap"):
            guidebook.reasoning_guides.append({
                "title": "Investigation Roadmap",
                "scope": "full contract",
                "guide_content": parsed["investigation_roadmap"] if isinstance(parsed["investigation_roadmap"], str) else json.dumps(parsed["investigation_roadmap"]),
            })

        return guidebook

    # ── Adaptive depth computation ──

    def _compute_adaptive_depth(self, source_code: str) -> int:
        """
        Compute investigation depth from source code complexity.
        More complex protocols get more evaluation/refinement iterations.
        """
        complexity_score = 0

        # External calls indicate interaction complexity
        external_call_patterns = [
            r'\.transfer\(', r'\.transferFrom\(', r'\.call\{',
            r'\.delegatecall\(', r'\.staticcall\(', r'\.send\(',
            r'IERC20\(', r'IUniswap', r'IAave', r'IOracle',
        ]
        for pattern in external_call_patterns:
            complexity_score += len(re.findall(pattern, source_code))

        # State variables indicate state space
        state_vars = len(re.findall(r'^\s*(mapping|uint|int|bool|address|bytes)\b', source_code, re.MULTILINE))
        complexity_score += state_vars // 3

        # Oracle/price feeds
        if re.search(r'oracle|priceFeed|getPrice|latestRound|twap', source_code, re.IGNORECASE):
            complexity_score += 5

        # Callbacks and hooks
        if re.search(r'receive\(\)|fallback\(\)|onERC|Hook|Callback', source_code, re.IGNORECASE):
            complexity_score += 5

        # Assembly usage
        if re.search(r'\bassembly\s*\{', source_code):
            complexity_score += 3

        # Upgradeability
        if re.search(r'Upgradeable|Proxy|delegatecall|Initializable', source_code):
            complexity_score += 3

        # Lines of code (raw size)
        loc = source_code.count('\n')
        complexity_score += loc // 200

        if complexity_score <= 5:
            return 1  # Shallow
        elif complexity_score <= 15:
            return 2  # Moderate
        else:
            return 3  # Deep

    # ── JSON parsing utilities ──

    def _extract_json(self, text: str) -> Optional[dict]:
        """Extract JSON from LLM response text."""
        if not text:
            return None

        # Try ```json blocks first
        pattern = re.compile(r"```(?:json\s+)?(\{.*?\})```", re.DOTALL)
        match = pattern.search(text)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                try:
                    return commentjson.loads(match.group(1))
                except Exception:
                    pass

        # Try broader match
        pattern2 = re.compile(r"```(?:json\s+)?([\[{].*?[\]}])```", re.DOTALL)
        match2 = pattern2.search(text)
        if match2:
            try:
                parsed = json.loads(match2.group(1))
                if isinstance(parsed, list):
                    return {"investigation_prompts": parsed}
                return parsed
            except Exception:
                pass

        # Try entire text
        try:
            return json.loads(text)
        except Exception:
            pass

        return None

    def _parse_evaluation(self, raw_eval: str, iteration: int) -> dict:
        """Parse evaluation output into structured dict."""
        parsed = self._extract_json(raw_eval)
        if parsed:
            parsed["iteration"] = iteration
            # Ensure quality_score is float
            try:
                parsed["quality_score"] = float(parsed.get("quality_score", 0.0))
            except (TypeError, ValueError):
                parsed["quality_score"] = 0.0
            return parsed

        # Fallback: try to extract score from text
        score_match = re.search(r'"?quality_score"?\s*:\s*([0-9.]+)', raw_eval)
        score = float(score_match.group(1)) if score_match else 0.0

        return {
            "quality_score": score,
            "recommendation": "refine" if score < self.quality_threshold else "converge",
            "coverage_gaps": [],
            "depth_issues": [],
            "grounding_failures": [],
            "strengths": [],
            "raw_evaluation": raw_eval[:2000],
            "iteration": iteration,
        }

    def _extract_prompts_from_methodology(self, methodology: str) -> List[Dict]:
        """Extract investigation prompts from raw methodology text."""
        parsed = self._extract_json(methodology)
        if parsed and isinstance(parsed, dict):
            return parsed.get("investigation_prompts", [])
        return [{"raw_methodology": methodology[:5000]}]

    # ── Helper methods ──

    def _build_partial_guidebook(
        self, target_path, protocol_type, source_code,
        understanding, methodology, evaluation_history,
        quality_score, iteration,
    ) -> InvestigationGuidebook:
        """Build a partial guidebook for progressive export."""
        return InvestigationGuidebook(
            target_path=target_path,
            protocol_type=protocol_type,
            investigation_prompts=self._extract_prompts_from_methodology(methodology),
            evaluation_history=evaluation_history,
            final_quality_score=quality_score,
            iterations_to_converge=iteration,
            source_code_hash=hashlib.sha256(source_code.encode()).hexdigest()[:16],
            understanding=understanding[:3000],
        )

    def _empty_guidebook(self, target_path: str, protocol_type: str) -> InvestigationGuidebook:
        """Return an empty guidebook when the engine fails."""
        return InvestigationGuidebook(
            target_path=target_path,
            protocol_type=protocol_type,
            final_quality_score=0.0,
            iterations_to_converge=0,
        )
