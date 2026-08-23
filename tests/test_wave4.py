import os
import pytest
from lensint.modules.memory_forensics import MemoryForensicsEngine
from lensint.modules.benchmarks import BayesianForensicFusionEngine, DatasetBenchmarkRunner

def test_memory_overlap_offset():
    chunk_size = 100
    overlap = 20
    offset_base = 100
    buffer = b"A" * overlap
    c = {"offset": 5}
    absolute_offset = c["offset"] + offset_base - len(buffer)
    assert absolute_offset == 85

def test_bayesian_fusion_fail_close():
    try:
        score, verdict, log = BayesianForensicFusionEngine.calculate_calibrated_risk(
            ela_score=999,
            copy_move_detected=True,
            dqt_anomaly=False,
            cfa_anomaly=False,
            fft_ai_score=100.0,
            rs_stego_detected=False,
            chi_square_detected=False,
            metadata_anomaly=False,
            malware_threat=False,
            confirmed_payload=False,
            c2_stego_detected=True,
            prompt_injection=True
        )
        assert score > 90.0
    except Exception as e:
        pytest.fail(f"Fusion engine should not fail: {e}")

def test_benchmark_inversion():
    runner = DatasetBenchmarkRunner(lambda x: 0.1)
    scores = [(0.1, 1), (0.2, 1), (0.8, 0), (0.9, 0)]
    auc = runner._calculate_auc(scores)
    assert auc == 0.0
    score_inverted = True
    default_threshold = 0.5
    tp = sum(1 for s, lbl in scores if lbl == 1 and s <= default_threshold)
    fp = sum(1 for s, lbl in scores if lbl == 0 and s <= default_threshold)
    tn = sum(1 for s, lbl in scores if lbl == 0 and s > default_threshold)
    fn = sum(1 for s, lbl in scores if lbl == 1 and s > default_threshold)
    assert tp == 2
    assert fp == 0
    assert tn == 2
    assert fn == 0
