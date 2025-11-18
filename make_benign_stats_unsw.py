# make_benign_stats_unsw.py
import json
from pathlib import Path

import pandas as pd

from config import FEATURES, BENIGN_STATS_PATH

# 네 CSV 파일 경로로 수정
CSV_PATH = Path("UNSW_NB15_training-set.csv")
OUT_PATH = BENIGN_STATS_PATH


def main():
    print(f"[+] UNSW-NB15 로딩: {CSV_PATH}")
    df = pd.read_csv(CSV_PATH)

    # 1) 정상 레코드만 사용 (Label = 0)
    label_col_candidates = ["Label", "label"]
    label_col = None
    for c in label_col_candidates:
        if c in df.columns:
            label_col = c
            break
    if label_col is None:
        raise ValueError("CSV 안에 'Label' 또는 'label' 컬럼이 없습니다. 컬럼 이름을 확인하세요.")

    benign = df[df[label_col] == 0]
    print(f"   - 전체: {len(df)}행, 정상({label_col}=0): {len(benign)}행")

    if benign.empty:
        raise ValueError("정상(Label=0) 데이터가 없습니다.")

    # 2) 피처별 mean/std 계산
    stats: dict[str, dict[str, float]] = {}

    for name in FEATURES:
        if name not in benign.columns:
            print(f"   ! 경고: FEATURES에 '{name}'가 있는데 CSV에 이 컬럼이 없습니다. 건너뜀.")
            continue

        col = pd.to_numeric(benign[name], errors="coerce").dropna()
        if col.empty:
            print(f"   ! 경고: '{name}' 컬럼 값이 전부 NaN 입니다. 건너뜀.")
            continue

        mean = float(col.mean())
        std = float(col.std(ddof=0) or 1e-6)  # std=0이면 0 나눗셈 방지

        stats[name] = {"mean": mean, "std": std}
        print(f"   - {name}: mean={mean:.4f}, std={std:.4f}")

    if not stats:
        raise ValueError("어떤 피처도 통계를 계산하지 못했습니다. FEATURES/컬럼 이름을 다시 확인하세요.")

    # 3) JSON 저장
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n✅ benign_stats.json 저장 완료: {OUT_PATH}")


if __name__ == "__main__":
    main()