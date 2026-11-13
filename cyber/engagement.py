"""Persistent phase checkpoints for continuing an assessment without losing evidence."""
from copy import deepcopy
from pathlib import Path


def next_phase(record: dict, phases) -> int:
    """Older reports have no cursor; conservatively retry their first unfinished phase."""
    cursor = record.get("next_phase")
    if isinstance(cursor, int) and not isinstance(cursor, bool) and 0 <= cursor <= len(phases):
        return cursor
    statuses = {p.get("phase"): p.get("status") for p in record.get("phases", [])}
    skipped = record.get("skipped_phases", [])
    for index, (phase, *_rest) in enumerate(phases):
        if phase not in skipped and statuses.get(phase) != "ok":
            return index
    return len(phases)


def checkpoint_for(console, phases):
    from cyber.console import read_json
    from cyber.history import saved_results
    if console.engagement_path:
        path = Path(console.engagement_path)
        record = read_json(path)
        if record.get("target") == console.target and "phases" in record:
            if next_phase(record, phases) < len(phases):
                return path, record
    if console.session_id:
        for path, record in saved_results(console.state):
            if ("phases" in record and record.get("target") == console.target
                    and record.get("session_id") == console.session_id
                    and next_phase(record, phases) < len(phases)):
                return path, record
    return None


def prepare_resume(record: dict, path: Path, workspace: Path, phases) -> dict:
    record = deepcopy(record)
    record["next_phase"] = next_phase(record, phases)
    record.setdefault("run_stamp", path.stem.removeprefix("pentest-"))
    record.setdefault("workspace", str(workspace))
    record.setdefault("evidence_dir", str(Path(record["workspace"]) / "evidence" / record["run_stamp"]))
    record.setdefault("phase_reports", [])
    record.setdefault("skipped_phases", [])
    record["resumes"] = record.get("resumes", 0) + 1
    return record


def retain_phase(record: dict, report: dict, phase: str, label: str):
    """Keep every attempt's tools, but count each methodology phase only once."""
    report = dict(report, phase=phase)
    record["phase_reports"].append(report)
    status = report.get("summary", {}).get("status", "partial")
    if report.get("error") and report["error"] != "Operation stopped.":
        status = "stopped"
    prior = next((p for p in record["phases"] if p.get("phase") == phase), None)
    if prior is None:
        prior = {"phase": phase, "label": label, "elapsed": 0, "attempts": 0}
        record["phases"].append(prior)
    prior.update(status=status, elapsed=prior.get("elapsed", 0) + report.get("elapsed", 0),
                 attempts=prior.get("attempts", 1) + 1)
    record["tools"].extend(dict(tool, phase=phase) for tool in report.get("tools", []))
    record["findings"].extend(report.get("engagement_findings") or [])
    record["limitations"].extend(report.get("limitations", []))
    if report.get("error"):
        record["limitations"].append(f"{label}: {report['error']}")
