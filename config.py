# ============================================
# file: config.py
# ============================================
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

# ✅ Mendeley Ransomware PE Header Dataset 기준 피처 (0~1023 바이트)
FEATURES = [str(i) for i in range(1024)]  # "0", "1", ..., "1023"

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


ADJUST_PROB_GAMMA = 0.3