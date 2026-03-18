import json
import os
import uuid
from datetime import datetime
from typing import Dict, Any


REPORT_DIR = "openclay_reports"


def _ensure_report_dir():
    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)


def create_report(
    attack_id: str,
    attack_category: str,
    shield_level: str,
    model_name: str,
) -> Dict[str, Any]:
    """
    Create an empty OpenClay Security Report (PSR).
    """
    return {
        "metadata": {
            "run_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "attack_id": attack_id,
            "attack_category": attack_category,
            "shield_level": shield_level,
            "model_name": model_name,
        },

        "input_shield": {
            "blocked": None,
            "reason": None,
            "signals": {},
            "canary_inserted": False,
            "canary_value": None,
        },

        "model_execution": {
            "system_prompt_used": None,
            "user_input": None,
            "raw_model_output": None,
        },

        "output_shield": {
            "blocked": None,
            "reason": None,
            "canary_detected": False,
            "pii_findings": [],
        },

        "final_openclay_action": None,
        "constraints_applied": [],
    }


def update_section(report: Dict[str, Any], section: str, data: Dict[str, Any]) -> None:
    """
    Update a section of the report in-place.
    """
    if section not in report:
        raise ValueError(f"Invalid report section: {section}")

    report[section].update(data)


def set_final_action(
    report: Dict[str, Any],
    action: str,
    constraints: list | None = None,
) -> None:
    """
    Set final OpenClay action.
    """
    report["final_openclay_action"] = action
    if constraints:
        report["constraints_applied"] = constraints


def save_report(report: Dict[str, Any]) -> str:
    """
    Persist the report as a JSON file.
    """
    _ensure_report_dir()

    attack_id = report["metadata"]["attack_id"]
    run_id = report["metadata"]["run_id"]

    filename = f"psr_{attack_id}_{run_id}.json"
    filepath = os.path.join(REPORT_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return filepath
