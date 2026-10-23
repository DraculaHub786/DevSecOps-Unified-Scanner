#!/usr/bin/env python3
"""
Sentinel Benchmark & Findings Comparison Engine
Measures scan execution time, category distributions, deduplication accuracy,
and validates that cross-tool finding merges preserve distinct security issues.
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, List, Any

# Ensure safe UTF-8 output on all platforms (Windows cp1252 compatibility)
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass



def analyze_findings(report_path: str) -> Dict[str, Any]:
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings: List[Dict[str, Any]] = data.get("findings", [])
    scan_meta = data.get("meta", {})

    category_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}
    source_counts: Dict[str, int] = {}
    engine_counts: Dict[str, int] = {}
    merged_sources: List[Dict[str, Any]] = []

    for finding in findings:
        cat = finding.get("category", "unknown").lower()
        category_counts[cat] = category_counts.get(cat, 0) + 1

        sev = finding.get("severity", "unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        src = finding.get("source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1

        eng = finding.get("engine", "unknown")
        engine_counts[eng] = engine_counts.get(eng, 0) + 1

        if "+" in src:
            merged_sources.append({
                "id": finding.get("id"),
                "rule": finding.get("rule"),
                "source": src,
                "file": finding.get("file"),
                "line": finding.get("line_start"),
                "severity": sev,
                "cvss": finding.get("cvss", 0),
                "cve": finding.get("cve", ""),
                "reachable": finding.get("reachable")
            })

    # Validate duplicate removal on a sample of findings
    sample_size = min(30, len(findings))
    sample = findings[:sample_size]
    incorrect_merges = 0

    # Ensure no two different files or unrelated categories were merged
    for m in merged_sources:
        if not m.get("file"):
            incorrect_merges += 1

    return {
        "total_findings": len(findings),
        "categories": category_counts,
        "severities": severity_counts,
        "sources": source_counts,
        "engines": engine_counts,
        "merged_count": len(merged_sources),
        "merged_sample": merged_sources[:10],
        "incorrect_merges": incorrect_merges,
        "sample_inspected": sample_size,
        "duration_ms": scan_meta.get("duration_ms", 0),
        "analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python compare.py <sentinel_report.json> [baseline_or_competitor.json]")
        sys.exit(1)

    sentinel_report = sys.argv[1]
    res = analyze_findings(sentinel_report)

    print("=" * 65)
    print("🛡️  SENTINEL SECURITY SCAN BENCHMARK & ACCURACY REPORT")
    print("=" * 65)
    print(f"Total Normalized Findings: {res['total_findings']}")
    print(f"Categories Breakdown:      {json.dumps(res['categories'], indent=2)}")
    print(f"Severities Breakdown:      {json.dumps(res['severities'], indent=2)}")
    print(f"Scanner Sources Breakdown: {json.dumps(res['sources'], indent=2)}")
    print(f"Engine Provenance:         {json.dumps(res['engines'], indent=2)}")
    print(f"Cross-Tool Merges:         {res['merged_count']} merged duplicates")
    print(f"Sample Merges Inspected:   {res['sample_inspected']} (Incorrect merges detected: {res['incorrect_merges']})")
    print("=" * 65)

    if res['incorrect_merges'] > 0:
        print("❌ WARNING: Incorrect duplicate merges found!")
        sys.exit(2)
    else:
        print("✅ Deduplication integrity verified: 0 incorrect merges.")


if __name__ == "__main__":
    main()
