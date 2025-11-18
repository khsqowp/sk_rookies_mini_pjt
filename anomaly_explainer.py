# ============================================
# file: anomaly_explainer.py
#  - 정상 통계 기반 z-score로 이상 피처 설명
# ============================================
import json
from typing import Dict, List

from config import FEATURES, BENIGN_STATS_PATH, FEATURE_DESCRIPTIONS


class AnomalyExplainer:
    def __init__(self, stats_path=BENIGN_STATS_PATH):
        with open(stats_path, encoding="utf-8") as f:
            self.stats: Dict[str, Dict[str, float]] = json.load(f)

    def explain(self, features: Dict[str, float], top_k: int = 5, z_th: float = 2.0) -> List[Dict]:
        """
        - features: 현재 파일의 피처 값
        - 반환: z-score 기준 상위 이상 피처 리스트
        """
        anomalies = []
        for name in FEATURES:
            val = float(features.get(name, 0.0))
            info = self.stats.get(name)
            if not info:
                continue
            mean = float(info.get("mean", 0.0))
            std = float(info.get("std", 1.0)) or 1e-6
            z = (val - mean) / std
            if abs(z) >= z_th:
                anomalies.append({
                    "feature": name,
                    "description": FEATURE_DESCRIPTIONS.get(name, name),
                    "value": val,
                    "mean": mean,
                    "std": std,
                    "z_score": z,
                })
        anomalies.sort(key=lambda x: abs(x["z_score"]), reverse=True)
        return anomalies[:top_k]