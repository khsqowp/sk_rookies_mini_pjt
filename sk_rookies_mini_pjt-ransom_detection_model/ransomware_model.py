# ransomware_model.py
from typing import Dict, Tuple, List, Optional, Any

import numpy as np
import joblib

from config import MODEL_PATH, FEATURES
from anomaly_explainer import AnomalyExplainer


class RansomwareModel:
    """
    - joblib 파일이 바로 sklearn 모델인 경우
    - 또는 {"model": clf, "scaler": scaler, "features": [...]} 같은 dict인 경우
    둘 다 지원하도록 구현.
    """

    def __init__(self, model_path: str | None = None):
        if model_path is None:
            model_path = MODEL_PATH

        saved: Any = joblib.load(model_path)

        self.model: Any = None
        self.scaler: Optional[Any] = None
        self.feature_names: List[str] = list(FEATURES)  # 기본값

        # 1) dict로 저장된 경우
        if isinstance(saved, dict):
            # 실제 모델 객체 찾기
            if "model" in saved:
                self.model = saved["model"]
            elif "clf" in saved:
                self.model = saved["clf"]
            else:
                # 최악의 경우: dict 자체를 모델로 쓰려 했다면 그대로 둠
                self.model = saved

            # 스케일러/정규화기가 있으면 같이 저장되어 있을 수 있음
            if "scaler" in saved:
                self.scaler = saved["scaler"]

            # 학습 때 사용한 피처 이름이 dict 안에 들어있으면 그걸 우선 사용
            if "feature_names" in saved:
                self.feature_names = list(saved["feature_names"])
            elif "features" in saved:
                self.feature_names = list(saved["features"])

        # 2) dict가 아니라 모델 객체가 바로 저장된 경우
        else:
            self.model = saved

        # 최소한 predict 메서드는 있어야 정상
        if not hasattr(self.model, "predict"):
            raise TypeError(
                "joblib로 로드한 객체에 'predict' 메서드가 없습니다.\n"
                f"type={type(self.model)}. "
                "모델을 저장할 때 joblib.dump(clf) 또는 "
                "joblib.dump({'model': clf, ...}) 형태였는지 확인해 주세요."
            )

        self.explainer = AnomalyExplainer()

    # ---------- 내부 유틸 ----------

    def _vectorize(self, features: Dict[str, float]) -> np.ndarray:
        """
        features dict -> 모델 입력 벡터 (피처 순서 맞춰서)
        """
        x = np.array(
            [[float(features.get(name, 0.0)) for name in self.feature_names]],
            dtype=float,
        )

        # 스케일러 있으면 적용
        if self.scaler is not None:
            x = self.scaler.transform(x)
        return x

    # ---------- 공용 API ----------

    def predict(self, features: Dict[str, float]) -> Tuple[int, float]:
        """
        - 반환: (label, prob_ransom)
          label: 0=정상, 1=랜섬웨어
        """
        x = self._vectorize(features)

        # 확률 있으면 그대로 사용
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(x)[0]
            prob_ransom = float(proba[1])
        else:
            # 확률이 없으면 decision_function을 시그모이드로 근사
            if hasattr(self.model, "decision_function"):
                score = float(self.model.decision_function(x)[0])
                prob_ransom = 1.0 / (1.0 + np.exp(-score))
            else:
                # 정말 아무것도 없으면 0/1 결과만 사용
                label = int(self.model.predict(x)[0])
                prob_ransom = float(label)
                return label, prob_ransom

        label = int(prob_ransom >= 0.5)  # 임계값 0.5 (필요 시 조정)
        return label, prob_ransom

    def predict_with_explanation(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        - 모델 예측 + 이상 피처 설명
        """
        label, prob = self.predict(features)
        anomalies = []
        if label == 1:
            anomalies = self.explainer.explain(features)
        return {
            "label": label,
            "prob_ransom": prob,
            "anomalies": anomalies,
        }
