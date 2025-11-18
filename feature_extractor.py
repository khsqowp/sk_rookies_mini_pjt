# feature_extractor.py
from pathlib import Path
from typing import Dict

from config import FEATURES


def extract_pe_header_features(path: Path, header_size: int = 1024) -> Dict[str, float]:
    """
    PE 파일의 처음 1024바이트를 읽어서
    Mendeley 데이터셋과 동일한 형식의 피처 딕셔너리로 변환.
    """
    path = Path(path)
    data = path.read_bytes()

    # 1024 바이트보다 짧으면 0으로 패딩
    if len(data) < header_size:
        data = data + b"\x00" * (header_size - len(data))
    else:
        data = data[:header_size]

    features: Dict[str, float] = {}
    for i in range(header_size):
        byte_val = data[i]
        key = str(i)  # "0", "1", ..., "1023"
        if key in FEATURES:
            features[key] = float(byte_val)

    return features
