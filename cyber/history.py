"""Read-only saved-result index. Never expose raw agent conversations."""
from pathlib import Path
from datetime import datetime, timezone


def saved_results(state: Path) -> list[tuple[Path, dict]]:
    from cyber.console import read_json
    result = []
    for path in sorted((state / "results").glob("*.json"), reverse=True):
        record = read_json(path)
        if isinstance(record.get("tools"), list) and ("summary" in record or "phases" in record):
            result.append((path, record))
    def timestamp(row):
        value = str(row[1].get("started") or row[0].stem.removeprefix("pentest-"))
        try:
            return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            return row[0].stat().st_mtime
    result.sort(key=timestamp, reverse=True)
    return result[:100]
