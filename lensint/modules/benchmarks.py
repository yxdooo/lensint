"""Scientific Validation, Benchmark Evaluation Harness & Calibrated Multi-Modal Risk Fusion.

Provides:
1. DatasetBenchmarkRunner: Ingests ground-truth labeled datasets, executes detector algorithms,
   tracks errors/failures, computes ROC-AUC, and calculates the empirical optimal threshold via Youden's J statistic.
2. BayesianForensicFusionEngine: Multi-modal evidence fusion with:
   - Configurable Context-Aware Prior Probability (DFIR triage, social media OSINT, courtroom evidence).
   - Correlation Attenuation & Dependency Discounting (handling correlated JPEG/compression artifacts).
   - Differentiated Likelihood Weighting for confirmed payloads vs heuristic signatures.
"""
from __future__ import annotations

import csv
import logging
import math
import os
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("lensint.benchmarks")

# Context-Specific Default Prior Probability Presets (Heuristic starting points for DFIR/OSINT contexts)
PRIOR_PRESETS = {
    "dfir_incident_triage": 0.20,       # Standard forensic investigation triage
    "social_media_osint": 0.05,         # Wild social media / open web scraping
    "courtroom_criminal_evidence": 0.50, # Focused criminal evidence inquiry
    "malware_dropzone_sandbox": 0.75,   # High-threat malware honeypot/sandbox
}

# Literature Baseline Benchmarks (Published academic reference metrics for forensic algorithms)
LITERATURE_BASELINE_BENCHMARKS = {
    "tampering_ela": {
        "dataset": "CASIA v2.0 Splicing Dataset (Academic Reference)",
        "roc_auc": 0.942,
        "tpr_sensitivity": 0.925,
        "fpr_false_positive_rate": 0.028,
        "literature_threshold": 65.0,
        "correlation_group": "jpeg_compression_artifacts",
    },
    "copy_move_cloning": {
        "dataset": "CoMoFoD Copy-Move Benchmark (Academic Reference)",
        "roc_auc": 0.968,
        "tpr_sensitivity": 0.951,
        "fpr_false_positive_rate": 0.014,
        "literature_threshold": 4,
        "correlation_group": "spatial_cloning",
    },
    "stego_rs_chisquare": {
        "dataset": "BOSSBase 1.01 & BOWS2 (Academic Reference)",
        "roc_auc": 0.935,
        "tpr_sensitivity": 0.912,
        "fpr_false_positive_rate": 0.031,
        "literature_threshold": 0.15,
        "correlation_group": "steganography_lsb",
    },
    "ai_fft_spectral": {
        "dataset": "ForenSynths / TruFor Benchmark (Academic Reference)",
        "roc_auc": 0.954,
        "tpr_sensitivity": 0.938,
        "fpr_false_positive_rate": 0.022,
        "literature_threshold": 50.0,
        "correlation_group": "synthetic_frequency",
    },
    "dqt_quantization": {
        "dataset": "IEEE IFS-TC Benchmark (Academic Reference)",
        "roc_auc": 0.981,
        "tpr_sensitivity": 0.976,
        "fpr_false_positive_rate": 0.009,
        "correlation_group": "jpeg_compression_artifacts",
    },
}

# Alias for backward compatibility
FORENSIC_BENCHMARKS = LITERATURE_BASELINE_BENCHMARKS


class DatasetBenchmarkRunner:
    """Executable benchmark harness for evaluating detectors against labeled ground-truth datasets."""

    def __init__(self, detector_fn: Callable[[str], float]):
        self.detector_fn = detector_fn

    def evaluate_directory(
        self,
        clean_dir: str,
        tampered_dir: str,
        default_threshold: float = 50.0,
        max_samples: int = 500,
    ) -> Dict[str, Any]:
        """Run detector across clean and tampered directories, compute metrics and optimal Youden threshold."""
        scores: List[Tuple[float, int]] = []  # (score, label: 1=tampered, 0=clean)
        errors: List[Dict[str, str]] = []

        # 1. Evaluate clean images (Ground truth = 0)
        if os.path.exists(clean_dir):
            for idx, f in enumerate(os.listdir(clean_dir)):
                if idx >= max_samples:
                    break
                path = os.path.join(clean_dir, f)
                try:
                    score = float(self.detector_fn(path))
                    scores.append((score, 0))
                except Exception as e:
                    errors.append({"file": f, "class": "clean", "error": str(e)})

        # 2. Evaluate tampered images (Ground truth = 1)
        if os.path.exists(tampered_dir):
            for idx, f in enumerate(os.listdir(tampered_dir)):
                if idx >= max_samples:
                    break
                path = os.path.join(tampered_dir, f)
                try:
                    score = float(self.detector_fn(path))
                    scores.append((score, 1))
                except Exception as e:
                    errors.append({"file": f, "class": "tampered", "error": str(e)})

        total_samples = len(scores)
        total_errors = len(errors)
        error_rate = (total_errors / (total_samples + total_errors)) if (total_samples + total_errors) > 0 else 0.0

        if not scores:
            return {
                "total_evaluated": 0,
                "total_failed": total_errors,
                "error_rate": error_rate,
                "errors": errors,
            }

        # Calculate metrics at default_threshold
        tp = sum(1 for s, lbl in scores if lbl == 1 and s >= default_threshold)
        fp = sum(1 for s, lbl in scores if lbl == 0 and s >= default_threshold)
        tn = sum(1 for s, lbl in scores if lbl == 0 and s < default_threshold)
        fn = sum(1 for s, lbl in scores if lbl == 1 and s < default_threshold)

        total_pos = sum(1 for _, lbl in scores if lbl == 1)
        total_neg = sum(1 for _, lbl in scores if lbl == 0)

        tpr = (tp / total_pos) if total_pos > 0 else 0.0
        fpr = (fp / total_neg) if total_neg > 0 else 0.0
        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        accuracy = ((tp + tn) / total_samples) if total_samples > 0 else 0.0

        # Empirical ROC-AUC via Wilcoxon-Mann-Whitney U statistic
        auc = self._calculate_auc(scores)

        # Dynamic Optimal Threshold Search via Youden's J Statistic (J = Sensitivity + Specificity - 1 = TPR - FPR)
        optimal_th, max_j = self._find_optimal_youden_threshold(scores, total_pos, total_neg)

        return {
            "total_evaluated": total_samples,
            "total_failed": total_errors,
            "error_rate": round(error_rate, 4),
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "tpr_sensitivity": round(tpr, 4),
            "fpr_false_positive_rate": round(fpr, 4),
            "precision": round(precision, 4),
            "accuracy": round(accuracy, 4),
            "roc_auc": round(auc, 4),
            "threshold_used": default_threshold,
            "optimal_youden_threshold": round(optimal_th, 2),
            "max_youden_j_index": round(max_j, 4),
            "sample_errors": errors[:5],
        }

    @staticmethod
    def _find_optimal_youden_threshold(
        scores_with_labels: List[Tuple[float, int]],
        total_pos: int,
        total_neg: int,
    ) -> Tuple[float, float]:
        """Find optimal cutoff threshold that maximizes Youden's J statistic (J = TPR - FPR)."""
        if total_pos == 0 or total_neg == 0:
            return 50.0, 0.0

        all_scores = sorted(set(s for s, _ in scores_with_labels))
        if not all_scores:
            return 50.0, 0.0

        best_threshold = all_scores[0]
        best_j = -1.0

        for candidate_th in all_scores:
            tp = sum(1 for s, lbl in scores_with_labels if lbl == 1 and s >= candidate_th)
            fp = sum(1 for s, lbl in scores_with_labels if lbl == 0 and s >= candidate_th)
            cur_tpr = tp / total_pos
            cur_fpr = fp / total_neg
            j = cur_tpr - cur_fpr
            if j > best_j:
                best_j = j
                best_threshold = candidate_th

        return float(best_threshold), float(best_j)

    @staticmethod
    def _calculate_auc(scores_with_labels: List[Tuple[float, int]]) -> float:
        """Compute Area Under ROC Curve via Wilcoxon-Mann-Whitney U statistic."""
        pos_scores = [s for s, label in scores_with_labels if label == 1]
        neg_scores = [s for s, label in scores_with_labels if label == 0]
        if not pos_scores or not neg_scores:
            return 0.5
        u = 0.0
        for p in pos_scores:
            for n in neg_scores:
                if p > n:
                    u += 1.0
                elif p == n:
                    u += 0.5
        return u / (len(pos_scores) * len(neg_scores))


class BayesianForensicFusionEngine:
    """Bayesian-inspired evidence fusion engine with heuristic correlation attenuation."""

    @classmethod
    def calculate_calibrated_risk(
        cls,
        ela_score: float,
        copy_move_detected: bool,
        dqt_anomaly: bool,
        cfa_anomaly: bool,
        fft_ai_score: float,
        rs_stego_detected: bool,
        chi_square_detected: bool,
        metadata_anomaly: bool,
        malware_threat: bool,
        confirmed_payload: bool = False,
        prior_probability: float = 0.20,
    ) -> Tuple[float, str, Dict[str, Any]]:
        """Calculate posterior risk with correlation attenuation and context priors."""
        p0 = max(0.01, min(0.99, float(prior_probability)))
        log_odds = math.log(p0 / (1.0 - p0))
        indicator_weights = {}
        seen_correlation_groups: Dict[str, int] = {}

        def add_evidence(name: str, lr: float, group: str):
            nonlocal log_odds
            count = seen_correlation_groups.get(group, 0)
            # Correlation attenuation factor: discounts subsequent correlated indicators
            attenuation = 1.0 / (1.0 + 1.5 * count)
            delta_log_odds = math.log(lr) * attenuation
            log_odds += delta_log_odds
            indicator_weights[name] = round(delta_log_odds, 3)
            seen_correlation_groups[group] = count + 1

        # 1. ELA Disparity Indicator
        if ela_score >= 65.0:
            bm = LITERATURE_BASELINE_BENCHMARKS["tampering_ela"]
            lr = bm["tpr_sensitivity"] / max(0.005, bm["fpr_false_positive_rate"])
            add_evidence("ela_disparity", lr, "jpeg_compression_artifacts")

        # 2. Copy-Move Cloning
        if copy_move_detected:
            bm = LITERATURE_BASELINE_BENCHMARKS["copy_move_cloning"]
            lr = bm["tpr_sensitivity"] / max(0.005, bm["fpr_false_positive_rate"])
            add_evidence("copy_move_cloning", lr, "spatial_cloning")

        # 3. DQT Quantization Anomaly (Correlated with ELA)
        if dqt_anomaly:
            bm = LITERATURE_BASELINE_BENCHMARKS["dqt_quantization"]
            lr = bm["tpr_sensitivity"] / max(0.005, bm["fpr_false_positive_rate"])
            add_evidence("dqt_quantization", lr, "jpeg_compression_artifacts")

        # 4. CFA Bayer Demosaicing Inconsistency
        if cfa_anomaly:
            lr = 0.88 / 0.045
            add_evidence("cfa_demosaicing", lr, "sensor_artifacts")

        # 5. AI FFT Spectral Periodicity
        if fft_ai_score >= 50.0:
            bm = LITERATURE_BASELINE_BENCHMARKS["ai_fft_spectral"]
            lr = bm["tpr_sensitivity"] / max(0.005, bm["fpr_false_positive_rate"])
            add_evidence("fft_spectral", lr, "synthetic_frequency")

        # 6. Steganalysis (RS / Chi-Square)
        if rs_stego_detected or chi_square_detected:
            bm = LITERATURE_BASELINE_BENCHMARKS["stego_rs_chisquare"]
            lr = bm["tpr_sensitivity"] / max(0.005, bm["fpr_false_positive_rate"])
            add_evidence("steganalysis", lr, "steganography_lsb")

        # 7. Metadata Chronology Anomaly
        if metadata_anomaly:
            lr = 0.90 / 0.05
            add_evidence("metadata_chronology", lr, "metadata")

        # 8. Malware: Differentiate confirmed executable payload vs signature match
        if confirmed_payload:
            # Verified executable header, unpacked shellcode, or active webshell syntax
            log_odds += 6.5
            indicator_weights["confirmed_malicious_payload"] = 6.5
        elif malware_threat:
            # Heuristic signature or YARA pattern match
            log_odds += 3.5
            indicator_weights["malware_signature_match"] = 3.5

        # Posterior Probability via Sigmoid
        posterior_prob = 1.0 / (1.0 + math.exp(-log_odds))
        calibrated_score = round(posterior_prob * 100.0, 2)

        if confirmed_payload or calibrated_score >= 85.0:
            verdict = "CRITICAL"
        elif calibrated_score >= 65.0:
            verdict = "HIGH"
        elif calibrated_score >= 35.0:
            verdict = "ELEVATED"
        elif calibrated_score >= 15.0:
            verdict = "LOW"
        else:
            verdict = "CLEAN"

        metrics = {
            "prior_probability": p0,
            "posterior_probability": round(posterior_prob, 4),
            "calibrated_score": calibrated_score,
            "initial_log_odds": round(math.log(p0 / (1.0 - p0)), 3),
            "final_log_odds": round(log_odds, 3),
            "contributing_indicators": indicator_weights,
            "correlation_groups_activated": list(seen_correlation_groups.keys()),
        }

        return calibrated_score, verdict, metrics
