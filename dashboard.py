import streamlit as st
import pandas as pd
import os
import json
from datetime import datetime
import time

# 분석 함수 임포트 (실제 실행 시 필요)
from log_analyzer import analyze_ransomware_pattern

# --- 1. 상수 및 기본 설정 ---
st.set_page_config(page_title="랜섬웨어 탐지 대시보드", layout="wide")

# 분석 결과를 저장할 디렉토리
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output_analysis")
# 사용자가 업로드한 파일을 임시 저장할 디렉토리
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")

# 디렉터리가 없으면 생성
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)


# --- 2. 차트 및 데이터 로드 함수 ---

def load_detection_logs():
    """
    output_analysis 디렉토리에서 모든 탐지 로그(JSON)를 읽어 DataFrame으로 반환합니다.
    """
    log_files = [os.path.join(OUTPUT_DIR, f) for f in os.listdir(OUTPUT_DIR) if f.endswith('.json')]
    if not log_files:
        return pd.DataFrame(columns=["timestamp", "filename", "attack_cat"])
    
    data = []
    for file in log_files:
        with open(file, 'r', encoding='utf-8') as f:
            data.append(json.load(f))
            
    return pd.DataFrame(data)

def display_charts(df):
    """
    탐지 로그 데이터프레임을 받아 공격 유형별 통계 차트를 표시합니다.
    """
    st.subheader("공격 유형별 탐지 통계")
    
    if df.empty:
        st.info("아직 탐지된 랜섬웨어 공격 패턴이 없습니다.")
        return
        
    # 'attack_cat' 별로 탐지 횟수 집계
    attack_counts = df['attack_cat'].value_counts().reset_index()
    attack_counts.columns = ['공격 유형', '탐지 횟수']
    
    st.bar_chart(attack_counts.set_index('공격 유형')['탐지 횟수'])
    
    with st.expander("전체 탐지 기록 보기"):
        st.dataframe(df.sort_values("timestamp", ascending=False))


# --- 3. 메인 대시보드 UI ---

st.title("🛡️ AI 기반 악성코드 탐지 시스템")
st.info("네트워크 로그 CSV 파일을 업로드하여 AI 분석을 받아보세요. (랜섬웨어, 애드웨어 등 다양한 공격 탐지)")

uploaded_file = st.file_uploader("CSV 파일 업로드", type=['csv'])

if st.button("분석 실행", disabled=(uploaded_file is None)):
    if uploaded_file is not None:
        # 1. 업로드된 파일 임시 저장
        temp_file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
            
        # 2. 분석 실행
        with st.spinner("AI가 업로드된 파일을 분석 중입니다... (최대 1분 소요)"):
            try:
                result = analyze_ransomware_pattern(temp_file_path)
            except Exception as e:
                # API 키가 없거나 잘못된 경우를 포함한 모든 예외 처리
                st.error(f"분석 중 심각한 오류가 발생했습니다. API 키 설정을 확인해주세요. 오류: {e}")
                result = {"error": str(e)}

        # 3. 분석 결과 표시
        st.subheader("AI 분석 결과")
        if result.get("error"):
            st.error(f"분석 실패: {result['error']}")
            # 오류 발생 시에도 로그를 남길 수 있도록 처리 (선택 사항)
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "filename": uploaded_file.name,
                "attack_cat": "Error", # 오류 발생 시 'Error'로 기록
                "is_ransomware": False,
                "report": result['error']
            }
        else:
            # 모든 분석 결과에 대해 로그 저장
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "filename": uploaded_file.name,
                "is_ransomware": result.get("is_ransomware", False),
                "is_malicious": result.get("is_malicious", False),
                "attack_cat": result.get("attack_cat", "Unknown"),
                "report": result.get("report", "리포트 생성 불가")
            }

            # 결과 표시
            if result.get("is_malicious", False):
                attack_type = result.get("attack_cat", "Unknown")

                # 랜섬웨어는 특별히 강조
                if result.get("is_ransomware", False):
                    st.error(f"🚨 **랜섬웨어 탐지!** - {attack_type}")
                    st.warning("⚠️ 즉시 시스템을 격리하고 보안팀에 연락하세요!")
                else:
                    st.warning(f"⚠️ **악성 코드 탐지** - {attack_type}")
            else:
                st.success("✅ 정상 트래픽으로 판단됩니다.")

            with st.expander("상세 분석 리포트 보기"):
                st.markdown(log_entry["report"])

        # 결과 로그 저장 (오류 발생 시에도 저장)
        log_filename = f"detection_{int(time.time())}.json"
        with open(os.path.join(OUTPUT_DIR, log_filename), 'w', encoding='utf-8') as f:
            json.dump(log_entry, f, indent=2)

# --- 4. 통계 차트 표시 ---
st.divider()
detection_df = load_detection_logs()
display_charts(detection_df)
