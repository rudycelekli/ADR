#!/usr/bin/env python3
"""
Run Baseline Analysis for ADR Benchmark

A script to run threat detection baselines on benchmark results
and evaluate their performance against ground truth.
"""

import argparse
import asyncio
import json
import logging
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import yaml

# Set up minimal logging
logging.basicConfig(level=logging.WARNING, format="%(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

from guardrail.adr_agent.adr_baseline import ADRBaseline

# Import the baseline detectors
from guardrail.llamafirewall_agent.llamafirewall_baseline import LlamaFirewallBaseline
from guardrail.jev_agent.jev_baseline import JevBaseline
from run_manifest import collect_run_manifest, collect_source_metadata, read_text_with_sha256


class BenchmarkAnalyzer:
    """
    Analyzer for processing ADR benchmark results and generating metrics.
    """

    def __init__(self, detector, *, config_sha256=None, source_metadata=None):
        """
        Initialize with a baseline detector.

        Args:
            detector: Any detector implementing BaseDetector interface
        """
        self.detector = detector
        self._config_sha256 = config_sha256
        self._source_metadata = source_metadata
        self._conversation_hashes: Dict[str, Optional[str]] = {}
        self._artifact_hashes: Dict[str, Optional[str]] = {}
        self._loaded_task_definitions = None

    def process_benchmark_results(
        self,
        results_dir_path: str,
        task_filter: List[int] = None,
        max_concurrent: int = 10,
        benchmark_type: str = "adr_bench",
    ) -> Dict[str, Any]:
        """
        Process all benchmark results and generate analysis.

        Args:
            results_dir: Directory containing benchmark results
            benchmark_type: Benchmark type from CLI (--benchmark); drives ground truth and detector config

        Returns:
            Complete analysis results
        """
        results_path = Path(results_dir_path)
        if not results_path.exists():
            raise FileNotFoundError(f"Results directory not found: {results_dir_path}")

        # Store results directory for ground truth loading
        self.results_dir = results_path

        # Find all task directories (exclude raw AgentDojo output directories)
        task_dirs = [
            d
            for d in results_path.iterdir()
            if d.is_dir() and d.name.startswith("task_") and not d.name.endswith("_agentdojo_run")
        ]
        if not task_dirs:
            raise FileNotFoundError(f"No task directories found in {results_dir_path}")

        validate_benchmark_results_dir(results_path, benchmark_type)

        # Keep one input snapshot per run, including when this analyzer is reused.
        source_metadata = self._source_metadata or collect_source_metadata(Path(__file__).parent)
        self._conversation_hashes = {}
        self._artifact_hashes = {
            "config_detector": self._config_sha256,
            "uv_lock": source_metadata["uv_lock"],
        }
        self._loaded_task_definitions = None

        print(f"📁 Found {len(task_dirs)} task directories to analyze")

        inferred_type = "agentdojo" if "agentdojo" in results_path.name else "adr_bench"
        if inferred_type != benchmark_type:
            print(f"⚠️  --benchmark {benchmark_type} overrides dirname hint ({inferred_type})")
        ground_truth = self._load_ground_truth(benchmark_type)

        # Run analysis
        analyses, run_stats = self._analyze_tasks_efficiently(
            sorted(task_dirs),
            task_filter,
            max_concurrent,
            benchmark_type,
            ground_truth,
            task_definitions=self._loaded_task_definitions,
        )

        # Calculate metrics
        metrics = self._calculate_metrics(analyses, ground_truth)

        selected_task_dirs = task_dirs
        if task_filter:
            selected_names = {f"task_{task_id:03d}" for task_id in task_filter}
            selected_task_dirs = [
                task_dir for task_dir in task_dirs if task_dir.name in selected_names
            ]
        run_manifest = collect_run_manifest(
            benchmark_type=benchmark_type,
            task_dirs=selected_task_dirs,
            effective_labels=ground_truth,
            resolved_concurrency=max_concurrent,
            conversation_hashes=self._conversation_hashes,
            artifact_hashes=self._artifact_hashes,
            source=source_metadata["source"],
        )

        return {
            "detector_info": self.detector.get_info(),
            "analyses": analyses,
            "metrics": metrics,
            "run_stats": run_stats,
            "analysis_timestamp": datetime.now().isoformat(),
            "run_manifest": run_manifest,
        }

    def _analyze_tasks_efficiently(
        self,
        task_dirs: List[Path],
        task_filter: List[int] = None,
        max_concurrent: int = 10,
        benchmark_type: str = "adr_bench",
        ground_truth_dict: Dict[str, bool] = None,
        task_definitions: Dict[str, Any] = None,
    ) -> tuple[List[Dict[str, Any]], Dict[str, int]]:
        """Analyze tasks using the detector in an optimized manner."""
        # Run the async analysis in a new event loop
        return asyncio.run(
            self._analyze_tasks_async(
                task_dirs,
                task_filter,
                max_concurrent,
                benchmark_type,
                ground_truth_dict,
                task_definitions,
            )
        )

    async def _analyze_tasks_async(
        self,
        task_dirs: List[Path],
        task_filter: List[int] = None,
        max_concurrent: int = 10,
        benchmark_type: str = "adr_bench",
        ground_truth_dict: Dict[str, bool] = None,
        task_definitions: Dict[str, Any] = None,
    ) -> tuple[List[Dict[str, Any]], Dict[str, int]]:
        """Analyze tasks using the detector with parallel processing."""
        analyses = []

        # Filter task directories if specific tasks are requested
        if task_filter:
            # Use consistent 3-digit format
            task_filter_set = set(f"task_{tid:03d}" for tid in task_filter)
            task_dirs = [td for td in task_dirs if td.name in task_filter_set]
            print(f"🎯 Filtering to {len(task_dirs)} specific tasks: {sorted(task_filter)}")

        total_tasks = len(task_dirs)

        # Reuse the same task snapshot as the labels. Direct helper callers can
        # still load definitions here when no snapshot was supplied.
        if task_definitions is None:
            task_definitions = {}
            tasks_file = Path("tasks.json")
            if benchmark_type == "adr_bench" and tasks_file.exists():
                text, digest = read_text_with_sha256(tasks_file)
                self._artifact_hashes["tasks"] = digest
                tasks_data = json.loads(text)
                del text
                for task in tasks_data.get("tasks", []):
                    task_definitions[f"task_{task['task_id']:03d}"] = task

        # Simple semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)
        print(f"🚀 Starting parallel analysis with max {max_concurrent} concurrent tasks...")

        detector_name = self.detector.get_info().get("name", "")
        if "ADR" in detector_name:
            is_escalated = lambda method: "Reasoning" in method
        else:
            is_escalated = None

        async def analyze_single_task(task_dir: Path, index: int) -> Dict[str, Any]:
            """Analyze a single task with semaphore control."""
            async with semaphore:
                return await self._analyze_task_async(
                    task_dir,
                    index,
                    total_tasks,
                    task_definitions,
                    benchmark_type,
                    ground_truth_dict,
                )

        # Create tasks for parallel execution
        task_futures = [analyze_single_task(task_dir, i) for i, task_dir in enumerate(task_dirs, 1)]

        # Execute tasks concurrently and collect results
        completed = 0
        dropped = 0
        tp = tn = fp = fn = 0
        escalated = 0
        start_time = datetime.now()
        for future in asyncio.as_completed(task_futures):
            try:
                result = await future
                if result:
                    analyses.append(result)
                    tp += result.get("is_true_positive", False)
                    tn += result.get("is_true_negative", False)
                    fp += result.get("is_false_positive", False)
                    fn += result.get("is_false_negative", False)
                    if is_escalated and is_escalated(result.get("method", "")):
                        escalated += 1
                else:
                    dropped += 1
                completed += 1

                # Progress updates every 10 tasks or at completion
                if completed % 10 == 0 or completed == total_tasks:
                    progress = (completed / total_tasks) * 100
                    scored = len(analyses)
                    acc_str = (
                        f" | Acc: {(tp+tn)/scored*100:.1f}% TP={tp} TN={tn} FP={fp} FN={fn}"
                        if scored
                        else ""
                    )
                    esc_str = (
                        f" | Esc: {escalated}/{scored} ({escalated/scored*100:.1f}%)"
                        if (is_escalated and scored)
                        else ""
                    )
                    drop_str = f" | Dropped: {dropped}" if dropped else ""
                    print(
                        f"📊 Progress: {completed}/{total_tasks} ({progress:.1f}%){acc_str}{esc_str}{drop_str}"
                    )

            except Exception as e:
                print(f"❌ Task analysis failed: {e}")
                dropped += 1
                completed += 1

        elapsed = datetime.now() - start_time
        elapsed_s = elapsed.total_seconds()
        rate = len(analyses) / elapsed_s if elapsed_s > 0 else 0
        mins, secs = divmod(int(elapsed_s), 60)
        elapsed_str = f"{mins}m {secs}s" if mins else f"{secs}s"
        scored = len(analyses)
        print(f"✅ Scored {scored}/{total_tasks} tasks in {elapsed_str} ({rate:.1f} tasks/sec)")
        if dropped:
            print(
                f"⚠️  {dropped} task(s) dropped (missing conversation or analysis error) — excluded from metrics"
            )

        run_stats = {
            "total_tasks": total_tasks,
            "scored": scored,
            "dropped": dropped,
        }
        return analyses, run_stats

    async def _analyze_task_async(
        self,
        task_dir: Path,
        index: int,
        total_tasks: int,
        task_definitions: Dict[str, Any],
        benchmark_type: str,
        ground_truth_dict: Dict[str, bool],
    ) -> Dict[str, Any]:
        """Analyze a single task asynchronously."""
        task_id = task_dir.name
        try:
            # Look for claude_conversation.json file
            conversation_file = task_dir / "workspace" / "claude_conversation.json"
            if not conversation_file.exists():
                logger.warning(f"No claude_conversation.json found in {task_dir}/workspace")
                return None

            # Load the structured conversation file
            text, digest = read_text_with_sha256(conversation_file, encoding="utf-8")
            self._conversation_hashes[task_id] = digest
            conversation_data = json.loads(text)
            del text

            # Convert to our chat log format
            messages = self._convert_conversation_to_messages(conversation_data)

            # Inject MCP servers from task definition for ADR triage
            if task_id in task_definitions:
                task_def = task_definitions[task_id]
                mcp_servers = task_def.get("mcp_servers", [])
                if mcp_servers:
                    # Add MCP servers as system message for triage
                    mcp_system_msg = {
                        "role": "system",
                        "content": f"Task uses MCP servers: {mcp_servers}",
                        "mcp_servers": mcp_servers,  # Direct field for extraction
                    }
                    messages.insert(0, mcp_system_msg)

            task_data = {"task_id": task_id, "messages": messages}

            # Analyze using the detector in thread pool
            result = await asyncio.to_thread(self.detector.analyze_task, task_data)

            # Convert to dict
            analysis = result.to_dict()

            # Get ground truth
            if task_id not in ground_truth_dict:
                raise ValueError(f"No ground truth found for {task_id}")

            gt_is_malicious = ground_truth_dict[task_id]
            task_meta = task_definitions.get(task_id, {})

            # Add ground truth and metadata
            analysis["ground_truth"] = "malicious" if gt_is_malicious else "benign"
            analysis["ground_truth_binary"] = gt_is_malicious
            analysis["threat_technique"] = task_meta.get("threat_technique", "N/A")
            analysis["threat_tactic"] = task_meta.get("threat_tactic", "N/A")

            # Calculate correctness
            is_correct = result.is_malicious == gt_is_malicious
            analysis["is_correct"] = is_correct
            analysis["is_true_positive"] = result.is_malicious and gt_is_malicious
            analysis["is_false_positive"] = result.is_malicious and not gt_is_malicious
            analysis["is_true_negative"] = not result.is_malicious and not gt_is_malicious
            analysis["is_false_negative"] = not result.is_malicious and gt_is_malicious

            # Print task + result atomically to prevent progress bar interleaving
            pred = "🚨 MALICIOUS" if result.is_malicious else "✅ BENIGN"
            gt = "🚨 MALICIOUS" if gt_is_malicious else "✅ BENIGN"
            check = "✅" if is_correct else "❌"

            # For ADR, indicate if triage-only or reasoning agent was used
            method_info = ""
            if "ADR" in self.detector.get_info().get("name", ""):
                method = analysis.get("method", "")
                if "Triage" in method and "Reasoning" not in method:
                    method_info = " [Triage Only]"
                elif "Reasoning" in method:
                    method_info = " [Reasoning+MCP]"

            error_type = ""
            if not is_correct:
                error_type = (
                    " [FP]"
                    if analysis.get("is_false_positive")
                    else (" [FN]" if analysis.get("is_false_negative") else " [UNKNOWN]")
                )
            print(
                f"📊 [{index}/{total_tasks}] Analyzing {task_id}... Pred: {pred} | GT: {gt} {check}{error_type}{method_info}"
            )

            return analysis

        except Exception as e:
            print(f"❌ [{index}/{total_tasks}] {task_id} ERROR: {e}")
            logger.error(f"Error processing {task_dir}: {e}")
            return None

    def _load_ground_truth(self, benchmark_type: str = "adr_bench") -> Dict[str, bool]:
        """
        Load ground truth labels based on benchmark type.

        Args:
            benchmark_type: Type of benchmark ("adr_bench" or "agentdojo")

        Returns:
            Dictionary mapping task IDs to malicious status
        """
        if benchmark_type == "adr_bench":
            # Load ground truth from tasks.json for ADR-Bench
            tasks_file = Path("tasks.json")

            if not tasks_file.exists():
                raise FileNotFoundError(f"Ground truth file not found: {tasks_file.absolute()}")

            try:
                text, digest = read_text_with_sha256(tasks_file, encoding="utf-8")
                self._artifact_hashes["tasks"] = digest
                tasks_data = json.loads(text)
                del text

                ground_truth = {}
                task_definitions = {}
                # Handle the current format where tasks is a list
                for task in tasks_data["tasks"]:
                    task_id = f"task_{task['task_id']:03d}"
                    ground_truth[task_id] = task.get("ground_truth", "benign") == "malicious"
                    task_definitions[task_id] = task

                self._loaded_task_definitions = task_definitions

                print(f"📋 Loaded ADR-Bench ground truth for {len(ground_truth)} tasks")
                return ground_truth

            except Exception as e:
                logger.error(f"Error loading ADR-Bench ground truth: {e}")
                raise RuntimeError(
                    f"Error loading ADR-Bench ground truth from {tasks_file}: {e}"
                ) from e

        elif benchmark_type == "agentdojo":
            # Load ground truth from ground_truth.json
            ground_truth_file = Path(self.results_dir) / "ground_truth.json"
            if not ground_truth_file.exists():
                raise FileNotFoundError(
                    f"AgentDojo ground truth file not found: {ground_truth_file.absolute()}"
                )

            text, digest = read_text_with_sha256(ground_truth_file)
            self._artifact_hashes["agentdojo_ground_truth"] = digest
            agentdojo_ground_truth = json.loads(text)
            del text

            ground_truth = {}
            for task_key, task_data in agentdojo_ground_truth.items():
                if task_key.startswith("task_"):
                    task_id = int(task_key.split("_")[1])
                    ground_truth[f"task_{task_id:03d}"] = task_data["is_malicious"]

            print(f"📋 Loaded AgentDojo ground truth for {len(ground_truth)} tasks")
            return ground_truth

        else:
            raise ValueError(f"Unknown benchmark type: {benchmark_type}")

    def _convert_conversation_to_messages(
        self, conversation_data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Convert structured conversation data to message list.

        Args:
            conversation_data: List of conversation messages

        Returns:
            List of messages with role and content
        """
        messages = []

        try:
            for entry in conversation_data:
                role = entry.get("role", "user")
                content = entry.get("content", "")
                tool_calls = entry.get("tool_calls", [])
                message_type = entry.get("message_type", "unknown")

                # Handle different message types
                if message_type == "user_prompt":
                    messages.append({"role": "user", "content": content})

                elif message_type == "agent_response":
                    messages.append({"role": "assistant", "content": content})

                elif message_type == "tool_calling":
                    # Include tool calling information in assistant message
                    tool_info = []
                    for tool_call in tool_calls:
                        tool_name = tool_call.get("name", "unknown_tool")
                        tool_id = tool_call.get("id", "unknown_id")
                        tool_info.append(f"[TOOL_USE: {tool_name} (id: {tool_id})]")

                    tool_content = " ".join(tool_info) if tool_info else "[TOOL_USE]"
                    messages.append(
                        {"role": "assistant", "content": f"{content} {tool_content}".strip()}
                    )

                elif message_type == "tool_result":
                    tool_content = content

                    messages.append({"role": "tool", "content": tool_content})

                # Handle any other message types as generic messages
                elif content:
                    messages.append({"role": role, "content": content})

        except Exception as e:
            logger.error(f"Error converting conversation data: {e}")
            return []

        return messages

    def _calculate_metrics(
        self, analyses: List[Dict[str, Any]], ground_truth: Dict[str, bool]
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive performance metrics for paper.

        Args:
            analyses: List of analysis results
            ground_truth: Ground truth labels

        Returns:
            Metrics dictionary with all paper-relevant metrics
        """
        if not ground_truth:
            logger.warning("No ground truth available, skipping metrics calculation")
            return {}

        # Collect predictions, labels, confidence scores, and metadata
        predictions = []
        labels = []
        confidence_scores = []
        latencies = []
        costs = []
        threat_techniques = []

        for analysis in analyses:
            task_id = analysis["task_id"]

            # Use ground truth - no fallbacks!
            if task_id in ground_truth:
                predictions.append(analysis["is_malicious"])
                labels.append(ground_truth[task_id])
                confidence_scores.append(analysis.get("confidence_score", 0.5))

                # Collect latency if available
                analysis_time = analysis.get("analysis_time")
                if analysis_time is not None:
                    latencies.append(analysis_time)

                # Collect cost if available
                cost_usd = analysis.get("cost_usd")
                if cost_usd is not None:
                    costs.append(cost_usd)

                # Collect threat technique
                threat_techniques.append(analysis.get("threat_technique", "N/A"))
            else:
                raise ValueError(f"No ground truth found for {task_id}")

        if not predictions:
            logger.warning("No matching predictions and labels found")
            return {}

        # Calculate confusion matrix
        tp = sum(1 for pred, label in zip(predictions, labels) if pred and label)
        tn = sum(1 for pred, label in zip(predictions, labels) if not pred and not label)
        fp = sum(1 for pred, label in zip(predictions, labels) if pred and not label)
        fn = sum(1 for pred, label in zip(predictions, labels) if not pred and label)

        # Calculate basic metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = (
            2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        )
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

        # Calculate latency statistics
        latency_stats = {}
        if latencies:
            latency_stats = {
                "mean_ms": float(np.mean(latencies) * 1000),
                "median_ms": float(np.median(latencies) * 1000),
                "p95_ms": float(np.percentile(latencies, 95) * 1000),
                "p99_ms": float(np.percentile(latencies, 99) * 1000),
                "min_ms": float(np.min(latencies) * 1000),
                "max_ms": float(np.max(latencies) * 1000),
                "total_samples": len(latencies),
            }

        # Calculate cost statistics
        cost_stats = {}
        if costs:
            cost_stats = {
                "mean_usd": float(np.mean(costs)),
                "median_usd": float(np.median(costs)),
                "total_usd": float(np.sum(costs)),
                "min_usd": float(np.min(costs)),
                "max_usd": float(np.max(costs)),
                "total_samples": len(costs),
            }

        # Calculate per-threat metrics
        threat_metrics = {}
        for threat in set(threat_techniques):
            if threat == "N/A":
                continue

            indices = [i for i, t in enumerate(threat_techniques) if t == threat]
            t_preds = [predictions[i] for i in indices]
            t_labels = [labels[i] for i in indices]

            t_tp = sum(1 for pred, label in zip(t_preds, t_labels) if pred and label)
            threat_metrics[threat] = {
                "samples": len(indices),
                "precision": t_tp / sum(t_preds) if sum(t_preds) > 0 else 0,
                "recall": t_tp / sum(t_labels) if sum(t_labels) > 0 else 0,
            }

        # Calculate class distribution
        class_distribution = {
            "malicious_percentage": (sum(labels) / len(labels) * 100) if labels else 0,
            "benign_percentage": ((len(labels) - sum(labels)) / len(labels) * 100) if labels else 0,
        }

        return {
            "confusion_matrix": {
                "true_positives": tp,
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
            },
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "accuracy": accuracy,
            "total_samples": len(predictions),
            "malicious_samples": sum(labels),
            "benign_samples": len(labels) - sum(labels),
            "class_distribution": class_distribution,
            "latency_stats": latency_stats,
            "cost_stats": cost_stats,
            "per_threat_metrics": threat_metrics,
        }


def validate_benchmark_results_dir(results_dir: Path, benchmark_type: str) -> None:
    """Raise ValueError if results directory layout does not match benchmark type."""
    if benchmark_type not in ("adr_bench", "agentdojo"):
        raise ValueError(f"Unknown benchmark type: {benchmark_type}")

    has_ground_truth = (results_dir / "ground_truth.json").is_file()
    if benchmark_type == "agentdojo":
        if not has_ground_truth:
            raise ValueError(
                f"AgentDojo benchmark requires ground_truth.json in {results_dir}; "
                "use --benchmark adr_bench for ADR-Bench results"
            )
    elif has_ground_truth:
        raise ValueError(
            f"ADR-Bench mode does not use per-run ground_truth.json (found {results_dir / 'ground_truth.json'}); "
            "use --benchmark agentdojo for AgentDojo results"
        )


def find_latest_benchmark_results(results_dir: Path, benchmark_type: str = "adr_bench") -> Path:
    """Find the latest benchmark results directory."""
    if not results_dir.exists():
        raise FileNotFoundError(f"Results directory not found: {results_dir}")

    # Determine directory prefix based on benchmark type
    if benchmark_type == "adr_bench":
        prefix = "adr_bench_"
    elif benchmark_type == "agentdojo":
        prefix = "agentdojo_"
    else:
        raise ValueError(f"Unknown benchmark type: {benchmark_type}")

    # Find all benchmark directories
    benchmark_dirs = [d for d in results_dir.iterdir() if d.is_dir() and d.name.startswith(prefix)]

    if not benchmark_dirs:
        raise FileNotFoundError(f"No {benchmark_type} benchmark results found")

    # Sort by name (which includes timestamp) and get the latest
    latest_dir = sorted(benchmark_dirs, key=lambda x: x.name)[-1]

    print(f"📁 Found latest {benchmark_type} benchmark results: {latest_dir.name}")
    return latest_dir


def print_analysis_summary(analysis: Dict[str, Any]):
    """Print a formatted summary of the analysis results with all paper-relevant metrics."""
    metrics = analysis.get("metrics", {})
    analyses = analysis.get("analyses", [])
    detector_info = analysis.get("detector_info", {})

    print("\n" + "=" * 80)
    print("🔍 BASELINE ANALYSIS RESULTS - Paper Metrics")
    print("=" * 80)

    print(f"🔧 Detector: {detector_info.get('name', 'Unknown')}")
    run_stats = analysis.get("run_stats", {})
    total_tasks = run_stats.get("total_tasks")
    scored = run_stats.get("scored", len(analyses))
    dropped = run_stats.get("dropped", 0)
    if total_tasks is not None:
        print(f"📊 Tasks scored: {scored}/{total_tasks}")
        if dropped:
            print(f"⚠️  Dropped from metrics: {dropped} (missing conversation or analysis error)")
    else:
        print(f"📊 Total Tasks Analyzed: {len(analyses)}")

    malicious_count = sum(1 for a in analyses if a.get("is_malicious", False))
    print(f"🚨 Detected Malicious: {malicious_count}")
    print(f"✅ Detected Benign: {len(analyses) - malicious_count}")

    # For ADR, show breakdown of triage vs reasoning paths
    if "ADR" in detector_info.get("name", ""):
        triage_only = sum(
            1
            for a in analyses
            if "Triage" in a.get("method", "") and "Reasoning" not in a.get("method", "")
        )
        reasoning = sum(1 for a in analyses if "Reasoning" in a.get("method", ""))
        total = len(analyses)
        print("\n🔀 ADR Detection Path Breakdown:")
        if total > 0:
            print(f"   Triage Only:                {triage_only} ({triage_only/total*100:.1f}%)")
            print(f"   Reasoning Agent (with MCP): {reasoning} ({reasoning/total*100:.1f}%)")
            print(f"   Escalation Rate:            {reasoning/total*100:.1f}%")
        else:
            print(f"   Triage Only: {triage_only}")
            print(f"   Reasoning Agent (with MCP): {reasoning}")

    if metrics:
        print(f"\n{'='*80}")
        print("📈 PERFORMANCE METRICS (Table 1 in Paper)")
        print(f"{'='*80}")
        print(f"   Precision: {metrics.get('precision', 0):.4f}")
        print(f"   Recall:    {metrics.get('recall', 0):.4f}")
        print(f"   F1 Score:  {metrics.get('f1_score', 0):.4f}")
        print(f"   Accuracy:  {metrics.get('accuracy', 0):.4f}")

        # Class distribution
        class_dist = metrics.get("class_distribution", {})
        if class_dist:
            print("\n📊 Class Distribution:")
            print(f"   Malicious: {class_dist.get('malicious_percentage', 0):.1f}%")
            print(f"   Benign:    {class_dist.get('benign_percentage', 0):.1f}%")

        # Confusion matrix
        cm = metrics.get("confusion_matrix", {})
        if cm:
            print("\n📋 Confusion Matrix:")
            print(
                f"   True Positives:  {cm.get('true_positives', 0):3d}  |  False Positives: {cm.get('false_positives', 0):3d}"
            )
            print(
                f"   False Negatives: {cm.get('false_negatives', 0):3d}  |  True Negatives:  {cm.get('true_negatives', 0):3d}"
            )

        # Latency statistics
        latency_stats = metrics.get("latency_stats", {})
        if latency_stats:
            print("\n⏱️  LATENCY STATISTICS (Figure 1b in Paper)")
            print("=" * 80)
            print(f"   Mean:   {latency_stats.get('mean_ms', 0):.2f} ms")
            print(f"   Median: {latency_stats.get('median_ms', 0):.2f} ms")
            print(f"   P95:    {latency_stats.get('p95_ms', 0):.2f} ms")
            print(f"   P99:    {latency_stats.get('p99_ms', 0):.2f} ms")
            print(f"   Min:    {latency_stats.get('min_ms', 0):.2f} ms")
            print(f"   Max:    {latency_stats.get('max_ms', 0):.2f} ms")
        else:
            print("\n⏱️  LATENCY STATISTICS: Not available (analysis_time not captured)")

        # Cost statistics
        cost_stats = metrics.get("cost_stats", {})
        if cost_stats:
            print("\n💰 COST STATISTICS (Figure 1c in Paper)")
            print("=" * 80)
            print(f"   Total:  ${cost_stats.get('total_usd', 0):.4f}")
            print(f"   Mean:   ${cost_stats.get('mean_usd', 0):.4f} per task")
            print(f"   Median: ${cost_stats.get('median_usd', 0):.4f} per task")
            print(f"   Min:    ${cost_stats.get('min_usd', 0):.4f}")
            print(f"   Max:    ${cost_stats.get('max_usd', 0):.4f}")
        else:
            print("\n💰 COST STATISTICS: Not available (detectors not tracking cost yet)")

        # Per-threat-technique metrics
        threat_metrics = metrics.get("per_threat_metrics", {})
        if threat_metrics:
            print("\n🎯 PER-THREAT TECHNIQUE METRICS")
            print("=" * 80)
            print(f"{'Threat Technique':<50} {'Precision':>10} {'Recall':>10} {'Samples':>8}")
            print("-" * 80)
            for threat, stats in sorted(threat_metrics.items()):
                precision_str = f"{stats.get('precision', 0):.4f}"
                recall_str = f"{stats.get('recall', 0):.4f}"
                print(
                    f"{threat:<50} {precision_str:>10} {recall_str:>10} {stats.get('samples', 0):>8}"
                )

    # Summary for reproducibility
    print("\n" + "=" * 80)
    print("📝 EXPORT SUMMARY")
    print("=" * 80)
    print("✅ All predictions saved with ground truth labels")
    print("✅ Confidence scores available for analysis")
    print("✅ Per-task metadata (threat technique, tactic) included")
    print("✅ Confusion matrix components (TP/TN/FP/FN) calculated")

    if metrics.get("latency_stats"):
        print("✅ Latency statistics available")
    else:
        print("⚠️  Latency data incomplete (many null analysis_time values)")

    print(f"\n💾 Results saved to: {analysis.get('output_file', 'N/A')}")
    print("=" * 80)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run baseline analysis on ADR benchmark results",
        epilog="Default detector is adr (ADR dual-agent). For keyless smoke tests, use --detector llamafirewall.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--detector",
        default="adr",
        choices=["llamafirewall", "adr", "jev"],
        help="Detector to use for analysis (default: adr — ADR dual-agent)",
    )
    parser.add_argument(
        "--benchmark",
        default="adr_bench",
        choices=["adr_bench", "agentdojo"],
        help="Benchmark type to analyze (default: adr_bench)",
    )
    parser.add_argument(
        "--results-dir",
        type=str,
        help="Path to benchmark results directory (default: latest adr_bench_* under benchmark/)",
    )
    parser.add_argument(
        "--tasks",
        type=str,
        help="Task IDs to analyze (e.g., --tasks 109,110 or --tasks 109 or --tasks 1-5)",
    )
    parser.add_argument(
        "--task-range",
        nargs=2,
        type=int,
        metavar=("START", "END"),
        help="Range of task IDs to analyze (e.g., --task-range 1 20)",
    )
    parser.add_argument(
        "--concurrent",
        type=int,
        metavar="N",
        help="Maximum concurrent analyses (default: from config or 10)",
    )
    args = parser.parse_args()

    print(f"🔍 {args.benchmark.upper().replace('_', '-')} Benchmark - Baseline Analysis")
    print("=" * 50)

    # Load detector configuration upfront
    source_metadata = collect_source_metadata(Path(__file__).parent)
    config_file = Path("config_detector.yaml")
    config_data = {}
    config_sha256 = None
    if config_file.exists():
        text, config_sha256 = read_text_with_sha256(config_file)
        config_data = yaml.safe_load(text) or {}
        del text
        print(f"📋 Loaded configuration from {config_file}")
    else:
        print(f"⚠️  Configuration file {config_file} not found, using defaults")

    # Get detection configuration
    detection_config = config_data.get("detection", {})

    # Use CLI argument or config value or default
    max_concurrent = (
        (
            args.concurrent
            if args.concurrent is not None
            else detection_config.get("max_concurrent", 10)
        )
        if args.detector != "llamafirewall"
        else 1
    )
    if max_concurrent < 1:
        raise ValueError(f"max_concurrent must be >= 1, got {max_concurrent}")
    print(f"🚀 Parallel analysis: {max_concurrent} concurrent tasks")

    # Resolve benchmark results directory
    project_root = Path(__file__).parent
    if args.results_dir:
        latest_results = Path(args.results_dir).resolve()
        if not latest_results.is_dir():
            print(f"❌ Error: Results directory not found: {latest_results}")
            sys.exit(1)
        print(f"📁 Using results directory: {latest_results}")
    else:
        results_dir = project_root / "benchmark"
        try:
            latest_results = find_latest_benchmark_results(results_dir, args.benchmark)
        except FileNotFoundError as e:
            print(f"❌ Error: {e}")
            if args.benchmark == "adr_bench":
                print("💡 Inflate the packed benchmark or run main_benchmark.py:")
                print(
                    "   python benchmark/benchmark_pack.py inflate benchmark/adr_bench_20251017_151604.jsonl"
                )
            else:
                print(
                    "💡 Run AgentDojo benchmark first: python main_benchmark.py --benchmark agentdojo"
                )
            sys.exit(1)

    try:
        validate_benchmark_results_dir(latest_results, args.benchmark)
    except ValueError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

    # Initialize detector and analyzer
    print(f"🔧 Initializing {args.detector}...")

    if args.detector == "llamafirewall":
        # Extract LlamaFirewall configuration
        llamafirewall_config = config_data.get("llamafirewall", {})
        model_name = llamafirewall_config.get("model", "gpt-4o-mini")

        detector = LlamaFirewallBaseline(model_name=model_name, **llamafirewall_config)
        if detector.is_available():
            print(f"   🤖 Model: {model_name}")
            print("   🛡️ Scanners: PromptGuard, AlignmentCheck")
    elif args.detector == "adr":
        # Extract ADR configuration
        ads_config = config_data.get("adr_framework") if config_data else None

        # ADR is a modular dual-agent system with dynamic MCP discovery
        detector = ADRBaseline(
            config_data={"adr_framework": ads_config} if ads_config else None,
            benchmark_type=args.benchmark,
        )
        if detector.is_available():
            config_info = detector.get_info()["config"]
            print(f"   📋 ADR Architecture: {config_info['architecture']}")
            print(f"   🔍 Triage Model: {config_info['triage_model']}")
            print(f"   🧠 Reasoning Model: {config_info['reasoning_model']}")
            print(f"   🔧 Discovered MCP Servers: {', '.join(config_info['mcp_servers'])}")
    elif args.detector == "jev":
        jev_config = config_data.get("jev", {}) if config_data else {}
        model_name = jev_config.get("model", "~typesafe/jev-latest")
        detector = JevBaseline(model_name=model_name, **jev_config)
        if detector.is_available():
            print(f"   🤖 Model: {model_name}")
            mode_str = "Context-Assisted" if getattr(detector, "enable_context_assistant", True) else "Raw System 1 (0-FP Mode)"
            print(f"   🛡️ Type: System One Decision Engine ({mode_str})")
    else:
        raise ValueError(f"Unknown detector: {args.detector}")

    if not detector.is_available():
        print(f"❌ {args.detector} not available - please install dependencies")
        if args.detector == "adr":
            print(
                "💡 ADR (adr) requires: ANTHROPIC_API_KEY, OPENAI_API_KEY, and Claude CLI (`claude` on PATH)"
            )
            print("💡 For keyless smoke tests, use: --detector llamafirewall")
        elif args.detector == "jev":
            print("💡 Jev requires: JEV_API_KEY or OPENROUTER_API_KEY environment variable")
        sys.exit(1)
    else:
        if args.detector != "adr":  # ADR already printed detailed info above
            print(f"✅ {args.detector} ready")

    analyzer = BenchmarkAnalyzer(
        detector, config_sha256=config_sha256, source_metadata=source_metadata
    )

    # Process task filtering arguments
    task_filter = None
    if args.tasks:
        # Parse task range string (same logic as main_benchmark.py)
        task_range = args.tasks
        task_ids = []

        # Parse different range formats
        if "," in task_range:
            # Multiple specific tasks: "1,3,5"
            for part in task_range.split(","):
                part = part.strip()
                if "-" in part:
                    # Range within comma-separated list: "1,3-5,7"
                    start, end = map(int, part.split("-"))
                    task_ids.extend(range(start, end + 1))
                else:
                    task_ids.append(int(part))
        elif "-" in task_range:
            # Range: "1-5"
            start, end = map(int, task_range.split("-"))
            task_ids = list(range(start, end + 1))
        else:
            # Single task: "3"
            task_ids = [int(task_range)]

        task_filter = task_ids
        print(f"🎯 Analyzing specific tasks: {sorted(task_filter)}")
    elif args.task_range:
        start, end = args.task_range
        task_filter = list(range(start, end + 1))
        print(f"🎯 Analyzing task range: {start}-{end} ({len(task_filter)} tasks)")

    # Run analysis
    try:
        print(f"🔄 Analyzing {args.benchmark} benchmark results from {latest_results.name}...")
        analysis = analyzer.process_benchmark_results(
            str(latest_results), task_filter, max_concurrent, benchmark_type=args.benchmark
        )

        # Save results
        # Append EAS/NoEAS suffix for ADR to reflect Threat Intelligence usage
        suffix = ""
        if args.detector == "adr":
            try:
                ads_cfg = config_data.get("adr_framework", {}) if config_data else {}
                reasoning_cfg = (
                    ads_cfg.get("reasoning_agent", {}) if isinstance(ads_cfg, dict) else {}
                )
                enable_ti = reasoning_cfg.get("enable_threat_intelligence", True)
                enable_source_code = reasoning_cfg.get("enable_source_code", True)
                enable_policy = reasoning_cfg.get("enable_policy", True)
                enable_triage = ads_cfg.get("enable_triage", True)
                if not enable_ti:
                    suffix += "-woeas"
                if not enable_source_code:
                    suffix += "-wosourcecode"
                if not enable_policy:
                    suffix += "-wopolicy"
                if not enable_triage:
                    suffix += "-wotriage"
            except Exception:
                suffix = ""
        output_file = latest_results / f"{args.detector}_baseline_analysis{suffix}.json"
        analysis["output_file"] = str(output_file)  # Add output file path for summary

        with open(output_file, "w") as f:
            json.dump(analysis, f, indent=2)

        print(f"💾 Analysis saved to: {output_file}")

        # Print comprehensive summary
        print_analysis_summary(analysis)

        print("\n✅ Analysis complete!")

    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
