    # ============================================
# file: streamlit_app.py (옵션)
#  - 로그 기반 시각화/분석 대시보드
#  - watcher.py 실행해서 logs/events.jsonl 쌓인 뒤 실행
# ============================================
# 실행: streamlit run streamlit_app.py
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from config import LOG_PATH

st.set_page_config(page_title="Ransomware Monitor", layout="wide")

st.title("🛡️ 랜섬웨어 실시간 모니터링 로그 뷰어")

if not LOG_PATH.exists():
    st.info("아직 생성된 로그가 없습니다. watcher.py를 먼저 실행해서 로그를 쌓아주세요.")
    st.stop()

rows = []
with LOG_PATH.open(encoding="utf-8") as f:
    for line in f:
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue

if not rows:
    st.info("로그 파일은 있지만 유효한 로그 레코드가 없습니다.")
    st.stop()

df = pd.DataFrame(rows)

# 요약
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("총 이벤트 수", len(df))
with col2:
    st.metric("탐지된 랜섬웨어 수", int((df["label"] == 1).sum()))
with col3:
    st.metric("평균 랜섬웨어 확률", f"{df['prob_ransom'].mean():.3f}")

# 필터
st.sidebar.header("필터")
label_filter = st.sidebar.selectbox("라벨 필터", ["전체", "정상(0)", "랜섬웨어(1)"])
if label_filter == "정상(0)":
    df_view = df[df["label"] == 0]
elif label_filter == "랜섬웨어(1)":
    df_view = df[df["label"] == 1]
else:
    df_view = df

st.subheader("이벤트 목록")
st.dataframe(
    df_view[["timestamp", "file_path", "label", "prob_ransom", "action", "action_result"]],
    use_container_width=True,
)

# 상세 보기
st.subheader("선택한 이벤트 상세")
idx = st.number_input("인덱스 선택 (0 ~ N-1)", min_value=0, max_value=len(df_view) - 1, value=0)
row = df_view.iloc[int(idx)]

st.write(f"**파일 경로:** {row['file_path']}")
st.write(f"**라벨:** {row['label']} (1=랜섬웨어)")
st.write(f"**랜섬웨어 확률:** {row['prob_ransom']:.3f}")
st.write(f"**액션:** {row['action']} → {row['action_result']}")

st.markdown("### 피처 값")
st.json(row["features"])

st.markdown("### 이상 피처 (Top)")
st.json(row.get("anomalies", []))