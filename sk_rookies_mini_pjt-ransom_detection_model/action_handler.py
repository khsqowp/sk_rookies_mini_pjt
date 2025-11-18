# ============================================
# file: action_handler.py
#  - 파일 삭제/로그 기록 담당 (질문은 watcher에서)
# ============================================
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from config import (
    DEFAULT_ACTION_ON_MALICIOUS,
    QUARANTINE_DIR,
    LOG_PATH,
)


def _write_log(entry: Dict):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def handle_action(
    file_path: Path,
    features: Dict[str, float],
    model_result: Dict,
    anomalies: List[Dict],
    action: str | None = None,
):
    """
    - action: "log" / "delete" / "quarantine"
      (질문/선택 로직은 watcher.py에서 처리해서 여기로 넘김)
    """
    if action is None:
        action = DEFAULT_ACTION_ON_MALICIOUS

    file_path = file_path.resolve()

    action_result = "none"
    target_path = None

    if action == "quarantine":
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        target_path = QUARANTINE_DIR / file_path.name
        try:
            shutil.move(str(file_path), str(target_path))
            action_result = f"quarantined:{target_path}"
        except Exception as e:
            action_result = f"quarantine_failed:{e}"
    elif action == "delete":
        try:
            file_path.unlink(missing_ok=True)
            action_result = "deleted"
        except Exception as e:
            action_result = f"delete_failed:{e}"
    else:
        action_result = "logged_only"

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "file_path": str(file_path),
        "label": model_result.get("label"),
        "prob_ransom": model_result.get("prob_ransom"),
        "features": features,
        "anomalies": anomalies,
        "action": action,
        "action_result": action_result,
    }
    _write_log(entry)

    return entry