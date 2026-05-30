import json
import re
import sys
from pathlib import Path

if len(sys.argv) < 4:
    print("Usage: python scripts/merge_outputs.py <output_dir> <server_type> <original_stem>")
    sys.exit(2)

output_dir = Path(sys.argv[1])
server_type = sys.argv[2]
original_stem = sys.argv[3]

pattern = re.compile(rf"^{re.escape(server_type)}_{re.escape(original_stem)}_part(\d{{3}})_(.+)$")
stage_dirs = [
    "collector_results",
    "parser_results",
    "normalizer_results",
    "preprocessor_results",
    "detector_results",
    "feature_results",
    "report",
]

for stage in stage_dirs:
    base = output_dir / stage
    if not base.exists():
        continue
    groups = {}
    for p in base.iterdir():
        m = pattern.match(p.name)
        if not m:
            continue
        idx = int(m.group(1))
        tail = m.group(2)
        groups.setdefault(tail, []).append((idx, p))

    for tail, parts in groups.items():
        parts_sorted = [p for _, p in sorted(parts, key=lambda x: x[0])]
        merged_path = base / f"{server_type}_{original_stem}_{tail}"
        print(f"Merging {len(parts_sorted)} parts into {merged_path}")
        # jsonl
        if tail.endswith('.jsonl') or tail.endswith('.ndjson'):
            if merged_path.exists():
                merged_path.unlink()
            for part in parts_sorted:
                with part.open('r', encoding='utf-8') as handle, merged_path.open('a', encoding='utf-8') as out:
                    for line in handle:
                        out.write(line)
                try:
                    part.unlink()
                except Exception:
                    pass
        elif tail.endswith('.csv'):
            if merged_path.exists():
                merged_path.unlink()
            header_written = False
            for part in parts_sorted:
                with part.open('r', encoding='utf-8') as handle, merged_path.open('a', encoding='utf-8') as out:
                    first = True
                    for line in handle:
                        if first:
                            first = False
                            if not header_written:
                                out.write(line)
                                header_written = True
                            continue
                        out.write(line)
                try:
                    part.unlink()
                except Exception:
                    pass
        elif tail.endswith('_run_summary.json') or tail.endswith('run_summary.json'):
            summaries = []
            for part in parts_sorted:
                try:
                    summaries.append(json.loads(part.read_text(encoding='utf-8')))
                    try:
                        part.unlink()
                    except Exception:
                        pass
                except Exception:
                    continue
            if not summaries:
                continue
            merged = summaries[0].copy()
            for s in summaries[1:]:
                for k, v in s.items():
                    if k not in merged:
                        merged[k] = v
                        continue
                    if isinstance(v, int) and isinstance(merged.get(k), int):
                        merged[k] = merged.get(k, 0) + v
                    elif isinstance(v, dict) and isinstance(merged.get(k), dict):
                        for kk, vv in v.items():
                            if isinstance(vv, int):
                                merged[k][kk] = merged[k].get(kk, 0) + vv
                    elif isinstance(v, list) and isinstance(merged.get(k), list):
                        merged[k].extend(v)
            merged_path.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding='utf-8')
        else:
            if merged_path.exists():
                merged_path.unlink()
            for part in parts_sorted:
                with part.open('r', encoding='utf-8') as handle, merged_path.open('a', encoding='utf-8') as out:
                    out.write(handle.read())
                try:
                    part.unlink()
                except Exception:
                    pass

# regenerate report
try:
    report_dir = output_dir / 'report'
    merged_summary_path = report_dir / f"{server_type}_{original_stem}_run_summary.json"
    alerts_path = output_dir / 'detector_results' / f"{server_type}_{original_stem}_alerts.jsonl"
    merged_summary = None
    if merged_summary_path.exists():
        merged_summary = json.loads(merged_summary_path.read_text(encoding='utf-8'))
    else:
        candidates = list(report_dir.glob(f"{server_type}_{original_stem}_*_run_summary.json"))
        if candidates:
            summaries = [json.loads(p.read_text(encoding='utf-8')) for p in candidates]
            merged = summaries[0].copy()
            for s in summaries[1:]:
                for k, v in s.items():
                    if k not in merged:
                        merged[k] = v
                        continue
                    if isinstance(v, int) and isinstance(merged.get(k), int):
                        merged[k] = merged.get(k, 0) + v
            merged_summary = merged

    if merged_summary is not None:
        merged_alerts = []
        if alerts_path.exists():
            with alerts_path.open('r', encoding='utf-8') as handle:
                for line in handle:
                    text = line.strip()
                    if text:
                        try:
                            merged_alerts.append(json.loads(text))
                        except Exception:
                            continue
        from src.reporting.report_generator import ReportGenerator
        report_text = ReportGenerator().generate(merged_summary, merged_alerts)
        report_file = report_dir / f"{server_type}_{original_stem}_report.md"
        report_file.write_text(report_text, encoding='utf-8')
except Exception as e:
    print('Warning: failed to regenerate report', e)

print('MERGE_SCRIPT_DONE')
