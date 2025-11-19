# ============================================
# file: config.py
# ============================================
import json
from pathlib import Path

# --- 기본 경로 ---
BASE_DIR = Path(__file__).resolve().parent

# 감시할 폴더 (예: Downloads)
DOWNLOAD_DIR = Path.home() / "Downloads"

# 랜섬웨어로 판단 시 격리할 폴더 (지금은 안 써도 됨, 옵션용)
QUARANTINE_DIR = BASE_DIR / "quarantine"

# 모델 & 통계 경로
MODEL_PATH = BASE_DIR / "models" / "ransom_model.pkl"
BENIGN_STATS_PATH = BASE_DIR / "models" / "benign_stats.json"

# 로그 저장 경로 (JSON Lines 형식)
LOG_PATH = BASE_DIR / "logs" / "events.jsonl"

# 분석 대상 확장자
ANALYSIS_EXTENSIONS = {
    ".exe", ".dll", ".zip", ".rar",
    ".doc", ".docx", ".xls", ".xlsx",
    ".pdf", ".js", ".vbs"
}

FEATURES_PATH = BASE_DIR / "models" / "ransomware_features.json"
if FEATURES_PATH.exists():
    FEATURES = json.loads(FEATURES_PATH.read_text(encoding="utf-8"))
else:
    # 아직 학습 전이라 json이 없으면, 일단 전체 0~1023 사용 (훈련용/디버그용)
    FEATURES = [str(i) for i in range(1024)]

# 확률 보정용 (0.5 근처 확률을 얼마나 키울지/줄일지)
ADJUST_PROB_GAMMA = 1.0

# 간단한 설명
FEATURE_DESCRIPTIONS = {
    str(i): f"PE 헤더 {i}번째 바이트 값" for i in range(1024)
}

# ➜ 브라우저 임시 다운로드 확장자: 검사/로그에서 완전히 제외
TEMP_EXTENSIONS = {
    ".tmp",
    ".crdownload",
    ".part",
}

# 기본 액션 (지금은 실제 삭제 여부를 watcher에서 물어보고 결정)
DEFAULT_ACTION_ON_MALICIOUS = "log"  # "log" / "delete" / "quarantine"

# 폴더 생성
for p in [MODEL_PATH.parent, LOG_PATH.parent]:
    p.mkdir(parents=True, exist_ok=True)

