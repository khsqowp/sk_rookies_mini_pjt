# ransomware_model.py
from typing import Dict, Tuple, Any

import numpy as np
import joblib

from config import MODEL_PATH, FEATURES, ADJUST_PROB_GAMMA
from anomaly_explainer import AnomalyExplainer


class RansomwareModel:
    def __init__(self, model_path: str | None = None):
        if model_path is None:
            model_path = MODEL_PATH

        self.model: Any = joblib.load(model_path)
        if not hasattr(self.model, "predict"):
            raise TypeError("모델에 predict 메서드가 없습니다.")

        self.feature_names = list(FEATURES)
        self.explainer = AnomalyExplainer()

    def _vectorize(self, features: Dict[str, float]) -> np.ndarray:
        return np.array(
            [[float(features.get(name, 0.0)) for name in self.feature_names]],
            dtype=float,
        )

    def predict(self, features: Dict[str, float]) -> Tuple[int, float]:
        x = self._vectorize(features)

        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(x)[0]
            prob_ransom = float(proba[1])
        else:
            if hasattr(self.model, "decision_function"):
                score = float(self.model.decision_function(x)[0])
                prob_ransom = 1.0 / (1.0 + np.exp(-score))
            else:
                label = int(self.model.predict(x)[0])
                prob_ransom = float(label)
                return label, prob_ransom

        if ADJUST_PROB_GAMMA is not None:
            prob_adj = float(prob_ransom ** ADJUST_PROB_GAMMA)
        else:
            prob_adj = prob_ransom

        # label은 "조정된 확률" 기준으로 판정
        label = int(prob_adj >= 0.5)

        return label, prob_adj

    def predict_with_explanation(self, features: Dict[str, float]) -> Dict[str, Any]:
        label, prob = self.predict(features)
        anomalies = []
        if label == 1:
            anomalies = self.explainer.explain(features)
        return {
            "label": label,            # 0=정상, 1=랜섬웨어
            "prob_ransom": prob,       # 랜섬웨어 확률
            "anomalies": anomalies,    # 이상 바이트 TOP K
        }
