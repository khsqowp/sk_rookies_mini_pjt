# ============================================
# file: feature_extractor.py
#  - 파일 기반 피처 추출 (static 분석 예시)
# ============================================
import math
from pathlib import Path
from typing import Dict

from config import FEATURES

SUSPICIOUS_KEYWORDS = [
    "encrypt", "decrypt", "ransom", "bitcoin",
    "aes", "rsa", "crypt", "locker", "key", "shadow",
]


def _calculate_entropy(data: bytes) -> float:
    """Shannon entropy 계산."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _extract_strings(data: bytes, min_len: int = 4):
    """바이너리에서 ASCII 문자열 추출."""
    result = []
    current = []
    for b in data:
        if 32 <= b <= 126:  # printable ASCII
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return result


def extract_features_from_file(path: Path) -> Dict[str, float]:
    """
    파일에서 랜섬웨어 탐지용 피처 추출.
    - 실제 모델 학습 시 동일한 로직 사용해야 함.
    """
    data = path.read_bytes()

    file_size = len(data)
    entropy = _calculate_entropy(data)
    strings = _extract_strings(data)
    num_strings = len(strings)
    string_density = num_strings / file_size if file_size > 0 else 0.0

    suspicious_count = 0
    lower_strings = [s.lower() for s in strings]
    for s in lower_strings:
        if any(keyword in s for keyword in SUSPICIOUS_KEYWORDS):
            suspicious_count += 1
    suspicious_ratio = suspicious_count / num_strings if num_strings > 0 else 0.0

    features = {
        "file_size_bytes": float(file_size),
        "entropy": float(entropy),
        "num_strings": float(num_strings),
        "string_density": float(string_density),
        "suspicious_string_ratio": float(suspicious_ratio),
    }

    # 모델 입력 피처 부족 시 0으로 채우기
    for name in FEATURES:
        features.setdefault(name, 0.0)

    return features