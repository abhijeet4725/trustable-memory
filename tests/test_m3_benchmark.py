"""
tests/test_m3_benchmark.py

End-to-end test for M3 benchmark:
  1. Executes the benchmark runner.
  2. Verifies benchmark/results.csv is generated and contains all scenario rows (8 auto + 2 manual).
  3. Verifies benchmark/results.png is generated and non-empty.
  4. Checks that new metrics (total_tainted_outputs, found_after_cleanup, still_serving_poison)
     match ground truth across baseline and graph.
  5. Verifies Attack 8 (large blast) metrics (20 total, 5 baseline found, 20 graph found).
  6. Verifies manual flag variants for attacks 6 and 7.
"""
from __future__ import annotations

import csv
import os

from benchmark.attacks import ATTACK_SCENARIOS
from benchmark.run_benchmark import run_benchmark


class TestM3Benchmark:
    def test_benchmark_runs_end_to_end_and_generates_outputs(self):
        results = run_benchmark()
        # 8 automatic scenarios + 2 manual flag variants = 10 rows
        assert len(results) == 10

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        csv_path = os.path.join(base_dir, "benchmark", "results.csv")
        png_path = os.path.join(base_dir, "benchmark", "results.png")

        assert os.path.exists(csv_path), "results.csv must exist"
        assert os.path.exists(png_path), "results.png must exist"
        assert os.path.getsize(png_path) > 1000, "results.png should contain image data"

        # Check CSV content
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 10, "CSV must have exactly 10 rows (8 auto + 2 manual flag)"

        by_id = {r["attack_id"]: r for r in rows}

        # Check standard auto attacks (1 to 5)
        for i in (1, 3, 4, 5):
            aid = f"attack_{i}_"
            matched = [r for r in rows if r["attack_id"].startswith(aid) and r["detection_mode"] == "automatic"]
            assert len(matched) == 1
            r = matched[0]
            assert int(r["total_tainted_outputs"]) == 2
            assert int(r["graph_found_after_cleanup"]) == 2
            assert int(r["graph_still_serving_poison_after_cleanup"]) == 0
            assert int(r["baseline_found_after_cleanup"]) == 1
            assert int(r["baseline_still_serving_poison_after_cleanup"]) == 1

        # Check Attack 8 (large blast)
        r8 = by_id["attack_8_large_blast"]
        assert int(r8["total_tainted_outputs"]) == 20
        assert int(r8["graph_found_after_cleanup"]) == 20
        assert int(r8["graph_still_serving_poison_after_cleanup"]) == 0
        assert int(r8["baseline_found_after_cleanup"]) == 5
        assert int(r8["baseline_still_serving_poison_after_cleanup"]) == 15
        assert int(r8["graph_false_quarantines"]) == 0

        # Check Attacks 6 & 7 in automatic mode (expected miss)
        r6_auto = by_id["attack_6_compromised_high_trust"]
        assert int(r6_auto["graph_found_after_cleanup"]) == 0
        assert int(r6_auto["graph_still_serving_poison_after_cleanup"]) == 2

        r7_auto = by_id["attack_7_sybil_consensus"]
        assert int(r7_auto["graph_found_after_cleanup"]) == 0
        assert int(r7_auto["graph_still_serving_poison_after_cleanup"]) == 2

        # Check Attacks 6 & 7 manual flag variants
        r6_man = by_id["attack_6_compromised_high_trust_manual"]
        assert r6_man["detection_mode"] == "manual_flag"
        assert int(r6_man["graph_found_after_cleanup"]) == 2
        assert int(r6_man["graph_still_serving_poison_after_cleanup"]) == 0
        assert int(r6_man["baseline_found_after_cleanup"]) == 1

        r7_man = by_id["attack_7_sybil_consensus_manual"]
        assert r7_man["detection_mode"] == "manual_flag"
        assert int(r7_man["graph_found_after_cleanup"]) == 2
        assert int(r7_man["graph_still_serving_poison_after_cleanup"]) == 0
        assert int(r7_man["baseline_found_after_cleanup"]) == 1
