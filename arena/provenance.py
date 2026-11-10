"""Source and scenario identifiers for attempt attribution; no private config contents."""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path


def source_revision(directory: Path) -> dict:
    directory = Path(directory)
    record = {"path": str(directory)}
    try:
        record["commit"] = subprocess.check_output(
            ["git", "-C", str(directory), "rev-parse", "HEAD"], text=True, stderr=subprocess.PIPE).strip()
        record["dirty"] = bool(subprocess.check_output(
            ["git", "-C", str(directory), "status", "--porcelain"], text=True, stderr=subprocess.PIPE).strip())
    except (OSError, subprocess.CalledProcessError) as exc:
        record["error"] = f"Source revision unavailable ({type(exc).__name__})"
    return record


def record_provenance(experiment, cfg) -> dict:
    record = {}
    for role, plugin in (("attacker", experiment.attacker), ("defender", experiment.defender)):
        field = getattr(plugin, "code_dir_field", None)
        if field:
            record[role] = source_revision(cfg.plugin_dir(field))
    if experiment.environment_config.environment_plugin == "mhbench":
        record["environment"] = source_revision(cfg.mhbench_dir)
    spec = Path(experiment.environment.resolve_spec(cfg))
    record["scenario"] = {"path": str(spec)}
    try:
        record["scenario"]["sha256"] = hashlib.sha256(spec.read_bytes()).hexdigest()
    except OSError as exc:
        record["scenario"]["error"] = f"Scenario unreadable ({type(exc).__name__})"
    return record
