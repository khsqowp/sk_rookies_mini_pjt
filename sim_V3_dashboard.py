"""
Dashboard v3 (Real-time Simulation)
- Simulates real-time log analysis based on a fixed CSV file.
- Implements smooth UI updates without full-page reloads.
- Includes an AI Analyst feature.
"""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import os
import time
from datetime import datetime
from openai import OpenAI
from dotenv import load_dotenv

# Import the V3 log analyzer
from sim_V3_log_analyzer import LogAnalyzer

# --- Initial Page Configuration ---
st.set_page_config(
    page_title="실시간 탐지 시뮬레이션 V3",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Environment and Constants ---
load_dotenv()
SIMULATION_FILE = "Mini_PJT2/100n1e.csv"
OUTPUT_DIR = "output_analysis"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- Caching and Setup ---
@st.cache_resource
def load_analyzer():
    """Load the log analysis engine silently."""
    return LogAnalyzer(silent=True)

@st.cache_resource
def load_simulation_data():
    """Load the simulation log file."""
    if not os.path.exists(SIMULATION_FILE):
        st.error(f"시뮬레이션 파일 '{SIMULATION_FILE}'을 찾을 수 없습니다.")
        return None
    return pd.read_csv(SIMULATION_FILE)

def get_ai_analysis(current_results_df):
    """Generates a security situation report using OpenAI."""
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        return "❌ OpenAI API 키가 설정되지 않았습니다. `.env` 파일을 확인해주세요."

    if current_results_df.empty:
        return "분석할 데이터가 없습니다. 시뮬레이션을 먼저 시작해주세요."

    client = OpenAI(api_key=api_key)
    
    total = len(current_results_df)
    malicious = current_results_df['is_malware'].sum()
    attack_dist = current_results_df[current_results_df['is_malware']]['attack_type'].value_counts().to_dict()
    
    context = f"""
    ## 현재 보안 탐지 현황 요약
    - 총 분석 로그 수: {total}
    - 탐지된 악성 로그 수: {malicious}
    - 악성 로그 비율: {malicious/total*100 if total > 0 else 0:.2f}%
    - 주요 공격 유형 분포: {attack_dist}
    """
    
    system_prompt = f"""당신은 최고의 사이버 보안 분석가입니다. 제공된 현재 보안 탐지 현황 요약을 바탕으로, 상황을 전문적으로 분석하고 평가 리포트를 작성해주세요. 리포트에는 다음 내용이 포함되어야 합니다:
    1.  **상황 개요**: 현재 탐지된 위협의 심각성을 평가합니다. (예: '초기 침투 단계', '경계 수준', '심각한 위협 확산 중' 등)
    2.  **주요 위협 분석**: 가장 많이 탐지된 공격 유형의 특징과 잠재적 위험을 설명합니다.
    3.  **권장 조치 사항**: 현재 상황에 기반한 즉각적인 대응 방안과 장기적인 보안 강화 방안을 구체적으로 제안합니다.
    - 답변은 반드시 한국어로, 마크다운 형식을 사용하여 명확하고 구조적으로 작성해주세요.
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": context}],
            temperature=0.5,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"❌ AI 분석 중 오류 발생: {e}"

# --- Session State Initialization ---
if 'simulation_running' not in st.session_state:
    st.session_state.simulation_running = False
if 'log_index' not in st.session_state:
    st.session_state.log_index = 0
if 'results_df' not in st.session_state:
    st.session_state.results_df = pd.DataFrame()
if 'time_series_data' not in st.session_state:
    st.session_state.time_series_data = []
if 'ai_analysis_report' not in st.session_state:
    st.session_state.ai_analysis_report = ""

# --- Load Resources ---
analyzer = load_analyzer()
simulation_df = load_simulation_data()

# --- UI ---
st.title("📡 실시간 위협 탐지 시뮬레이션 V3")

with st.sidebar:
    st.header("⚙️ 시뮬레이션 제어")
    if st.button("시뮬레이션 시작/중지", type="primary"):
        st.session_state.simulation_running = not st.session_state.simulation_running
        if st.session_state.log_index >= len(simulation_df): # Reset if finished
            st.session_state.log_index = 0
            st.session_state.results_df = pd.DataFrame()
            st.session_state.time_series_data = []
            st.session_state.ai_analysis_report = ""
    
    if st.button("결과 초기화"):
        st.session_state.simulation_running = False
        st.session_state.log_index = 0
        st.session_state.results_df = pd.DataFrame()
        st.session_state.time_series_data = []
        st.session_state.ai_analysis_report = ""
        st.rerun()

    speed = st.slider("시뮬레이션 속도 (초당 로그 수)", 1, 20, 5)
    sleep_interval = 1 / speed
    
    st.markdown("---")
    st.header("🤖 AI 분석")
    if st.button("AI 현재 상황 분석"):
        with st.spinner("AI가 현재 상황을 분석 중입니다..."):
            report = get_ai_analysis(st.session_state.results_df)
            st.session_state.ai_analysis_report = report
            st.rerun() # Rerun to show the report immediately

# Placeholders
metrics_placeholder = st.empty()
chart_placeholder = st.empty()
table_placeholder = st.empty()
ai_report_placeholder = st.empty()

# --- Main Loop ---
while st.session_state.simulation_running:
    if simulation_df is None or analyzer is None:
        st.error("시뮬레이션 초기화 실패.")
        st.session_state.simulation_running = False
        break

    log_idx = st.session_state.log_index
    if log_idx >= len(simulation_df):
        st.success("🎉 시뮬레이션 완료! 모든 로그를 처리했습니다.")
        st.session_state.simulation_running = False
        break

    current_log_row = simulation_df.iloc[log_idx]
    
    row_text = analyzer.row_to_text(current_log_row)
    analysis_result = analyzer.analyze_single_row(row_text, top_k=5)
    
    result_series = pd.Series(analysis_result)
    result_series['timestamp'] = datetime.now()
    
    new_result_df = pd.DataFrame([result_series])
    st.session_state.results_df = pd.concat([st.session_state.results_df, new_result_df], ignore_index=True)
    
    total = len(st.session_state.results_df)
    malicious = st.session_state.results_df['is_malware'].sum()
    st.session_state.time_series_data.append({'time': result_series['timestamp'], 'malware': malicious, 'benign': total - malicious})

    # --- Update UI Placeholders ---
    with metrics_placeholder.container():
        malware_ratio = (malicious / total * 100) if total > 0 else 0
        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        m_col1.metric("총 처리 로그", f"{total}/{len(simulation_df)}")
        m_col2.metric("정상 로그", f"{total - malicious:,} 개")
        m_col3.metric("악성 로그", f"{malicious:,} 개", delta=f"{malware_ratio:.1f}%" if malicious > 0 else "0.0%", delta_color="inverse")
        m_col4.metric("평균 확신도", f"{st.session_state.results_df['confidence'].mean():.2%}")

    with chart_placeholder.container():
        ts_df = pd.DataFrame(st.session_state.time_series_data)
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=ts_df['time'], y=ts_df['malware'], mode='lines', name='악성', line=dict(color='red')))
        fig.add_trace(go.Scatter(x=ts_df['time'], y=ts_df['benign'], mode='lines', name='정상', line=dict(color='green')))
        fig.update_layout(title="실시간 탐지 추이", xaxis_title="시간", yaxis_title="누적 로그 수")
        st.plotly_chart(fig, use_container_width=True)

    with table_placeholder.container():
        st.subheader("🚨 최신 악성 탐지 로그")
        display_df = st.session_state.results_df[st.session_state.results_df['is_malware']].copy()
        if not display_df.empty:
            display_df['timestamp'] = pd.to_datetime(display_df['timestamp']).dt.strftime('%H:%M:%S')
            st.dataframe(
                display_df[['timestamp', 'attack_type', 'confidence']].tail(10).sort_index(ascending=False),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("아직 탐지된 악성 로그가 없습니다.")

    st.session_state.log_index += 1
    time.sleep(sleep_interval)

# --- Final State Display ---
if not st.session_state.simulation_running:
    if st.session_state.results_df.empty:
        st.info("사이드바에서 '시뮬레이션 시작/중지' 버튼을 눌러 실시간 탐지를 시작하세요.")
    else:
        st.info("시뮬레이션이 중지되었습니다.")

if st.session_state.ai_analysis_report:
    with ai_report_placeholder.container():
        st.subheader("🤖 AI 분석 리포트")
        st.markdown(st.session_state.ai_analysis_report)
