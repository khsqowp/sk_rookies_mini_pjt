# anomaly_explainer.py
import json
from typing import Dict, List

from config import BENIGN_STATS_PATH, FEATURES, FEATURE_DESCRIPTIONS


class AnomalyExplainer:
    def __init__(self):
        data = json.loads(BENIGN_STATS_PATH.read_text(encoding="utf-8"))
        self.stats = data  # {feature: {"mean":..., "std":...}}

    def explain(self, features: Dict[str, float], top_k: int = 10) -> List[Dict]:
        results = []
        for name in FEATURES:
            if name not in self.stats:
                continue
            mean = self.stats[name]["mean"]
            std = self.stats[name]["std"] or 1e-6
            val = float(features.get(name, 0.0))
            z = (val - mean) / std

            results.append({
                "feature": name,
                "description": FEATURE_DESCRIPTIONS.get(name, ""),
                "value": val,
                "mean": mean,
                "std": std,
                "z_score": z,
                "abs_z": abs(z),
            })

        results.sort(key=lambda x: x["abs_z"], reverse=True)
        return results[:top_k]
