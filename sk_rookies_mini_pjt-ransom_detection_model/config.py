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

# 모델 입력 피처 이름 (순서 중요)
FEATURES = [
    "dur",
    "sbytes", "dbytes",
    "rate",
    "sttl", "dttl",
    "sload", "dload",
    "sloss", "dloss",
    "spkts", "dpkts",
    "sinpkt", "dinpkt",
    "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin",
    "tcprtt", "synack", "ackdat",
    "smean", "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
]

# 피처 설명 (관제/설명용)
FEATURE_DESCRIPTIONS = {
    "file_size_bytes": "파일 크기 (바이트)",
    "entropy": "파일 바이트 엔트로피 (난이도)",
    "num_strings": "감지된 ASCII 문자열 개수",
    "string_density": "파일 크기 대비 문자열 밀도",
    "suspicious_string_ratio": "의심 키워드(crypt, ransom 등) 비율",
}
# ➜ 브라우저 임시 다운로드 확장자: 검사/로그에서 완전히 제외
TEMP_EXTENSIONS = {
    ".tmp",
    ".crdownload",
    ".part",
}

# 기본 액션 (지금은 실제 삭제 여부를 watcher에서 물어보고 결정)
DEFAULT_ACTION_ON_MALICIOUS = "log"  # "log" / "delete" / "quarantine"

# 디렉터리 생성
for p in [QUARANTINE_DIR, MODEL_PATH.parent, LOG_PATH.parent]:
    p.mkdir(parents=True, exist_ok=True)