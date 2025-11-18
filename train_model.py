# train_mendeley_header_model.py
import json
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

from config import FEATURES, MODEL_PATH, BENIGN_STATS_PATH

CSV_PATH = Path(r"C:\Users\sec\OneDrive\바탕 화면\SK쉴더스\ransom_dectection_model\sk_rookies_mini_pjt\Ransomware_headers.csv")


def main():
    print(f"[+] Mendeley Ransomware PE Header Dataset 로딩: {CSV_PATH}")
    df = pd.read_csv(CSV_PATH)

    # 필수 컬럼 체크
    required_cols = {"GR", "ID", "filename", "family"}
    missing_req = [c for c in required_cols if c not in df.columns]
    if missing_req:
        raise ValueError(f"CSV에 필수 컬럼이 없습니다: {missing_req}")

    # 피처 컬럼 체크 (0~1023)
    missing_feats = [f for f in FEATURES if f not in df.columns]
    if missing_feats:
        raise ValueError(
            f"CSV에 없는 피처 컬럼이 있습니다. 예시: {missing_feats[:10]} ..."
        )

    X = df[FEATURES].astype(float).values
    y = df["GR"].astype(int).values  # 0 = goodware, 1 = ransomware

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        n_jobs=-1,
        random_state=42,
    )
    clf.fit(X_tr, y_tr)

    y_pred = clf.predict(X_te)
    print("\n[분류 리포트]")
    print(classification_report(y_te, y_pred))

    # 1) 모델 저장
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"\n✅ 모델 저장 완료: {MODEL_PATH}")

    # 2) 정상(GR=0) 기준 benign_stats.json 생성
    benign = df[df["GR"] == 0]
    stats = {}
    for name in FEATURES:
        col = benign[name].astype(float)
        mean = float(col.mean())
        std = float(col.std(ddof=0) or 1e-6)
        stats[name] = {"mean": mean, "std": std}
        print(f"   - {name}: mean={mean:.4f}, std={std:.4f}")

    BENIGN_STATS_PATH.parent.mkdir(parents=True, exist_ok=True)
    BENIGN_STATS_PATH.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\n✅ benign_stats.json 저장 완료: {BENIGN_STATS_PATH}")


if __name__ == "__main__":
    main()
