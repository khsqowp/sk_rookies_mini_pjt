"""
V4 통합 보안 대시보드
- 실시간 보안 관제, 상세 로그 분석, 리포팅 및 인사이트, 사고 대응 기능을 통합한 Streamlit 애플리케이션
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import os
import time
from datetime import datetime
import glob
from dotenv import load_dotenv
from streamlit_modal import Modal

# .env 파일에서 환경 변수 로드
load_dotenv()

# V4 분석 엔진 임포트
from V4_log_analyzer import LogAnalyzer

# --- 1. 페이지 및 기본 설정 ---
st.set_page_config(
    page_title="V4 통합 보안 대시보드",
    page_icon="🚀",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. 전역 변수 및 캐시 설정 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_DIR = os.path.join(BASE_DIR, "CSV Files")
OUTPUT_DIR = os.path.join(BASE_DIR, "output_analysis")
os.makedirs(OUTPUT_DIR, exist_ok=True)

@st.cache_resource
def load_analyzer():
    """로그 분석 엔진 로드 (캐싱)"""
    try:
        return LogAnalyzer(silent=True)
    except Exception as e:
        st.error(f"❌ 분석 엔진 초기화 실패: {e}")
        st.warning("벡터 DB가 생성되었는지 확인하세요. 'vector_db_builder.py'를 실행해야 할 수 있습니다.")
        return None

@st.cache_data
def get_csv_files():
    """분석 가능한 CSV 파일 목록 가져오기"""
    root_files = glob.glob(os.path.join(BASE_DIR, "*.csv"))
    csv_dir_files = glob.glob(os.path.join(CSV_DIR, "**", "*.csv"), recursive=True)
    all_files = root_files + csv_dir_files
    return sorted(list(set([os.path.basename(f) for f in all_files])))

# --- 3. 페이지 렌더링 함수 ---

def render_realtime_soc_dashboard():
    """페이지 1: 실시간 보안 관제 대시보드"""
    st.header("📡 실시간 보안 관제")
    st.markdown("---")

    attack_modal = Modal("🚨 고위험 위협 탐지!", key="attack_modal", padding=20, max_width=600)

    with st.sidebar:
        st.header("🕹️ 실시간 분석 제어")
        
        csv_files = get_csv_files()
        default_file = "08_30_2017-ra-pletor-alibaba-130a8a08dc6ac74fe7f7d70ee3c629b7.pcap_ISCX.csv"
        if default_file not in csv_files:
            default_file = next((f for f in ["simulation_log.csv", "100n1e.csv"] if f in csv_files), None)

        selected_file_basename = st.selectbox(
            "분석할 로그 파일을 선택하세요",
            options=csv_files,
            index=csv_files.index(default_file) if default_file and default_file in csv_files else 0,
            help="선택한 파일의 로그를 실시간으로 스트리밍하여 분석합니다."
        )

        speed = st.slider("분석 속도 (초당 로그 수)", 1, 50, 5)
        sleep_interval = 1 / speed
        
        confidence_threshold = st.slider("경고 확신도 임계값", 0.70, 1.00, 0.90, 0.01)

        c1, c2 = st.columns(2)
        if c1.button("▶️ 시작/중지", type="primary"):
            st.session_state.simulation_running = not st.session_state.get('simulation_running', False)
            if st.session_state.simulation_running and st.session_state.get('log_index', 0) >= len(st.session_state.get('simulation_df', [])):
                st.session_state.log_index = 0
                st.session_state.results_df = pd.DataFrame()
        
        if c2.button("🔄 초기화"):
            st.session_state.simulation_running = False
            st.session_state.log_index = 0
            st.session_state.results_df = pd.DataFrame()
            st.rerun()

    if 'simulation_running' not in st.session_state:
        st.session_state.simulation_running = False
    if 'log_index' not in st.session_state:
        st.session_state.log_index = 0
    if 'results_df' not in st.session_state:
        st.session_state.results_df = pd.DataFrame()

    if 'selected_file' not in st.session_state or st.session_state.selected_file != selected_file_basename:
        st.session_state.selected_file = selected_file_basename
        full_path = next((p for p in [os.path.join(BASE_DIR, selected_file_basename)] + glob.glob(os.path.join(CSV_DIR, "**", selected_file_basename), recursive=True) if os.path.exists(p)), None)

        if full_path:
            st.session_state.simulation_df = pd.read_csv(full_path)
            st.session_state.log_index = 0
            st.session_state.results_df = pd.DataFrame()
        else:
            st.error(f"파일을 찾을 수 없습니다: {selected_file_basename}")
            st.stop()

    simulation_df = st.session_state.simulation_df

    # --- UI 플레이스홀더 ---
    metrics_placeholder = st.empty()
    charts_placeholder = st.empty()
    table_placeholder = st.empty()

    # --- 메인 시뮬레이션 루프 ---
    if not st.session_state.simulation_running:
        results_df = st.session_state.results_df
        if results_df.empty:
            st.info("사이드바에서 '▶️ 시작/중지' 버튼을 눌러 실시간 분석을 시작하세요.")
        else:
            st.info("시뮬레이션이 중지되었습니다. 다시 시작하려면 '▶️ 시작/중지' 버튼을 누르세요.")

    while st.session_state.simulation_running:
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
        results_df = st.session_state.results_df
        malware_df = results_df[results_df['is_malware']]

        if analysis_result['is_malware'] and analysis_result['confidence'] >= confidence_threshold:
            st.session_state.incident = analysis_result
            attack_modal.open()

        with metrics_placeholder.container():
            total = len(results_df)
            malicious = len(malware_df)
            benign = total - malicious
            malware_ratio = (malicious / total * 100) if total > 0 else 0

            m_col1, m_col2, m_col3, m_col4 = st.columns(4)
            m_col1.metric("총 처리 로그", f"{total}/{len(simulation_df)}")
            m_col2.metric("정상 로그", f"{benign:,} 개")
            m_col3.metric("악성 로그", f"{malicious:,} 개", delta=f"{malware_ratio:.1f}%" if malicious > 0 else "0.0%", delta_color="inverse")
            m_col4.metric("평균 확신도", f"{malware_df['confidence'].mean():.2%}" if not malware_df.empty else "N/A")

        with charts_placeholder.container():
            c1, c2 = st.columns([3, 2])
            
            if not malware_df.empty:
                fig_scatter = px.scatter(malware_df, x='timestamp', y='confidence', color='attack_type', title="시간에 따른 악성 탐지 확신도", labels={'timestamp': '시간', 'confidence': '확신도'}, height=350)
                fig_scatter.update_layout(margin=dict(l=40, r=40, t=40, b=40))
                c1.plotly_chart(fig_scatter, use_container_width=True)
            else:
                c1.info("아직 탐지된 악성 로그가 없습니다.")

            attack_dist = malware_df['attack_type'].value_counts()
            if not attack_dist.empty:
                fig_bar = px.bar(x=attack_dist.index, y=attack_dist.values, title="공격 유형별 분포", labels={'x': '공격 유형', 'y': '탐지 수'}, color=attack_dist.index, height=350)
                fig_bar.update_layout(margin=dict(l=40, r=40, t=40, b=40))
                c2.plotly_chart(fig_bar, use_container_width=True)
            else:
                c2.info("탐지된 공격 유형이 없습니다.")

        with table_placeholder.container():
            if not malware_df.empty:
                display_df = malware_df.copy()
                display_df['timestamp'] = pd.to_datetime(display_df['timestamp']).dt.strftime('%H:%M:%S')
                st.dataframe(display_df[['timestamp', 'attack_type', 'confidence', 'source_ip', 'destination_ip']].tail(10).sort_index(ascending=False), use_container_width=True, hide_index=True)
            else:
                st.info("아직 탐지된 악성 로그가 없습니다.")
        
        st.session_state.log_index += 1
        time.sleep(sleep_interval)
    
    if st.session_state.simulation_running == False:
        st.rerun()
    
    if attack_modal.is_open() and 'incident' in st.session_state:
        with attack_modal.container():
            incident = st.session_state.incident
            st.error(f"**공격 유형:** {incident['attack_type']}")
            st.write(f"**탐지 확신도:** {incident['confidence']:.2%}")
            st.write(f"**출발지 IP:** {incident['source_ip']}")
            st.write(f"**목적지 IP:** {incident['destination_ip']}")
            st.code(incident['log_text'], language='text')
            
            if st.button("🚨 즉시 대응 페이지로 이동", type="primary"):
                st.session_state.page = "사고 대응"
                attack_modal.close()
                st.rerun()

def render_detailed_log_analysis():
    """페이지 2: 상세 로그 분석"""
    st.header("🔍 상세 로그 분석")
    st.markdown("---")
    st.info("CSV 파일을 업로드하여 전체 로그에 대한 심층 분석을 수행하고 결과를 확인할 수 있습니다.")

    def create_pie_chart(summary):
        fig = go.Figure(data=[go.Pie(labels=['악성 로그', '정상 로그'], values=[summary['malware_detected'], summary['benign_detected']], hole=0.4, marker=dict(colors=['#FF6B6B', '#51CF66']), textinfo='label+percent+value')])
        fig.update_layout(title_text=f"악성/정상 비율 (총 {summary['total_logs']:,}개)", showlegend=True)
        return fig

    def create_attack_distribution_chart(summary):
        attack_stats = summary['attack_stats']
        attack_types = list(attack_stats.keys())
        counts = [stats['count'] for stats in attack_stats.values()]
        fig = px.bar(x=attack_types, y=counts, title="공격 유형별 탐지 분포", labels={'x': '공격 유형', 'y': '탐지 횟수'}, color=attack_types)
        return fig

    def create_confidence_histogram(df):
        fig = px.histogram(df, x='confidence', nbins=50, title='탐지 확신도 분포', labels={'confidence': '확신도', 'count': '빈도'})
        return fig

    with st.sidebar:
        st.header("⚙️ 정적 분석 설정")
        use_sampling = st.checkbox("샘플링 사용 (빠른 테스트용)", value=True)
        sample_size = st.slider("샘플 크기", 100, 10000, 1000, 100) if use_sampling else None
    
    uploaded_file = st.file_uploader("분석할 네트워크 로그 CSV 파일을 업로드하세요.", type=['csv'])

    if st.button("🔬 분석 시작", disabled=(uploaded_file is None), type="primary"):
        if uploaded_file:
            with st.spinner("파일을 저장하고 분석을 준비합니다..."):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                temp_file_path = os.path.join(OUTPUT_DIR, f"upload_{timestamp}_{uploaded_file.name}")
                with open(temp_file_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
            
            with st.spinner(f"⚙️ 로그 분석 중... (샘플 크기: {sample_size or '전체'})"):
                try:
                    df_result, _ = analyzer.analyze_csv(temp_file_path, top_k=5, sample_size=sample_size)
                    summary = analyzer.generate_summary(df_result)
                    
                    output_filename = f"analysis_{timestamp}_{uploaded_file.name.replace('.csv', '')}.csv"
                    output_path = os.path.join(OUTPUT_DIR, output_filename)
                    df_result.to_csv(output_path, index=False)

                    st.session_state.static_analysis_result = {'df': df_result, 'summary': summary, 'output_path': output_path}
                    st.success("✅ 분석 완료!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ 분석 중 오류 발생: {e}")
                    st.code(traceback.format_exc())

    if 'static_analysis_result' in st.session_state:
        result = st.session_state.static_analysis_result
        summary = result['summary']
        df = result['df']

        st.markdown("---")
        st.header("📊 분석 결과")

        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        m_col1.metric("총 로그 수", f"{summary['total_logs']:,}개")
        m_col2.metric("악성 로그", f"{summary['malware_detected']:,}개", delta=f"{summary['malware_percentage']:.1f}%", delta_color="inverse")
        m_col3.metric("정상 로그", f"{summary['benign_detected']:,}개")
        m_col4.metric("평균 확신도", f"{summary['average_confidence']:.2%}")

        tab1, tab2, tab3, tab4 = st.tabs(["📊 개요", "📈 공격 분석", "📋 상세 데이터", "💾 다운로드"])

        with tab1:
            c1, c2 = st.columns(2)
            c1.plotly_chart(create_pie_chart(summary), use_container_width=True)
            c2.plotly_chart(create_confidence_histogram(df), use_container_width=True)
        with tab2:
            st.plotly_chart(create_attack_distribution_chart(summary), use_container_width=True)
            attack_details = [{'공격 유형': k, '탐지 횟수': v['count'], '비율 (%)': f"{v['percentage']:.1f}", '평균 확신도 (%)': f"{v['avg_confidence'] * 100:.1f}"} for k, v in summary['attack_stats'].items()]
            st.dataframe(pd.DataFrame(attack_details).sort_values('탐지 횟수', ascending=False), hide_index=True)
        with tab3:
            filter_malware = st.selectbox("악성 여부 필터", ["전체", "악성만", "정상만"])
            filtered_df = df[df['is_malware'] == True] if filter_malware == "악성만" else (df[df['is_malware'] == False] if filter_malware == "정상만" else df)
            st.dataframe(filtered_df.head(1000), use_container_width=True)
            if len(filtered_df) > 1000: st.info("상위 1,000개 행만 표시됩니다.")
        with tab4:
            st.download_button("📥 전체 결과 다운로드 (CSV)", df.to_csv(index=False).encode('utf-8'), os.path.basename(result['output_path']), 'text/csv')
            st.success(f"분석 결과가 `{result['output_path']}` 경로에 저장되었습니다.")

def render_reporting_and_insights():
    """페이지 3: 리포팅 및 인사이트"""
    st.header("📄 리포팅 및 인사이트")
    st.markdown("---")
    st.info("과거 분석 데이터를 기반으로 트렌드 리포트를 생성하고, 데이터에 대한 통찰을 얻습니다.")

    def get_ai_analysis_report(summary):
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key: return "❌ OpenAI API 키가 설정되지 않았습니다. `.env` 파일을 확인해주세요."
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        
        attack_stats_df = pd.DataFrame(summary['attack_stats']).T.reset_index()
        attack_stats_df.columns = ['Attack Type', 'Count', 'Percentage', 'Avg Confidence']
        attack_stats_df['Percentage'] = attack_stats_df['Percentage'].map('{:.2%}'.format)
        attack_stats_df['Avg Confidence'] = attack_stats_df['Avg Confidence'].map('{:.2%}'.format)
        markdown_table = attack_stats_df.to_markdown(index=False)

        context = f"## 보안 로그 분석 결과 요약\n- 총 로그 수: {summary['total_logs']}\n- 악성 로그 탐지: {summary['malware_detected']} ({summary['malware_percentage']:.2f}%)\n- 평균 탐지 확신도: {summary['average_confidence']:.2%}\n\n### 공격 유형별 상세 분석\n{markdown_table}"
        system_prompt = """당신은 최고의 사이버 보안 분석가입니다. 제공된 보안 로그 분석 결과를 바탕으로, 경영진에게 보고할 수 있는 수준의 전문적인 리포트를 작성해주세요. 리포트에는 다음 내용이 반드시 포함되어야 합니다:
        1.  **개요 (Executive Summary)**: 현재 상황을 한눈에 파악할 수 있도록 핵심 내용을 요약합니다. (위협 수준, 주요 발견 등)
        2.  **주요 위협 분석 (Key Threat Analysis)**: 가장 많이 탐지된 상위 3개 공격 유형에 대해 각각의 특징, 잠재적 위험, 그리고 비즈니스에 미칠 수 있는 영향을 설명합니다. **제공된 Markdown 테이블을 활용하여** 데이터를 명확하게 제시해주세요.
        3.  **탐지 동향 (Detection Trends)**: 탐지된 악성 로그들의 확신도(confidence)와 유사도 점수(similarity_score) 분포를 해석하고, 이것이 의미하는 바를 설명합니다. (예: '탐지 모델이 특정 유형의 공격에 대해 높은 확신도를 보이고 있음')
        4.  **권장 조치 사항 (Recommendations)**: 분석 결과에 기반하여 즉각적으로 수행해야 할 단기 조치와, 보안 강화를 위한 장기적인 전략을 구체적으로 제안합니다. (예: '특정 IP 대역 차단', '방화벽 룰 업데이트', '직원 보안 교육 강화' 등)
        - 답변은 반드시 한국어로, 마크다운 형식(#, ##, ###, **, - 등)을 사용하여 명확하고 구조적으로 작성해주세요."""
        
        try:
            response = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": context}], temperature=0.5)
            return response.choices[0].message.content
        except Exception as e:
            return f"❌ AI 리포트 생성 중 오류 발생: {e}"

    analysis_files = glob.glob(os.path.join(OUTPUT_DIR, "analysis_*.csv"))
    if not analysis_files:
        st.warning("분석된 데이터 파일이 없습니다. '상세 로그 분석' 페이지에서 먼저 분석을 실행해주세요.")
        st.stop()

    analysis_basenames = [os.path.basename(f) for f in analysis_files]
    selected_file = st.selectbox("분석할 리포트를 선택하세요", options=analysis_basenames)

    if selected_file:
        file_path = os.path.join(OUTPUT_DIR, selected_file)
        df = pd.read_csv(file_path)
        summary = analyzer.generate_summary(df)
        malware_df = df[df['is_malware']]

        st.markdown(f"### 📜 '{selected_file}' 분석 결과")

        c1, c2 = st.columns(2)
        with c1:
            st.subheader("공격 유형 계층 구조")
            if not malware_df.empty:
                fig_treemap = px.treemap(malware_df, path=[px.Constant("전체"), 'attack_type'], title="Treemap of Attack Types", height=400)
                fig_treemap.update_layout(margin=dict(l=20, r=20, t=50, b=20))
                st.plotly_chart(fig_treemap, use_container_width=True)
            else:
                st.info("탐지된 악성 로그가 없어 Treemap을 생성할 수 없습니다.")
        with c2:
            st.subheader("확신도 vs. 유사도 점수")
            if not malware_df.empty:
                fig_scatter = px.scatter(malware_df, x="similarity_score", y="confidence", color="attack_type", title="Confidence vs. Similarity Score", hover_data=['attack_type'], height=400)
                fig_scatter.update_layout(margin=dict(l=20, r=20, t=50, b=20))
                st.plotly_chart(fig_scatter, use_container_width=True)
            else:
                st.info("탐지된 악성 로그가 없어 Scatter plot을 생성할 수 없습니다.")

        st.markdown("---")
        st.subheader("🤖 AI 애널리스트 리포트")
        
        if 'ai_report' not in st.session_state or st.session_state.get('report_file') != selected_file:
            st.session_state.ai_report = ""

        if st.button("AI 리포트 생성", key="ai_report_btn"):
            with st.spinner("AI가 전문 분석 리포트를 생성 중입니다..."):
                report_text = get_ai_analysis_report(summary)
                st.session_state.ai_report = report_text
                st.session_state.report_file = selected_file
        
        if st.session_state.ai_report:
            st.markdown(st.session_state.ai_report)
            st.download_button("📥 리포트 다운로드 (Markdown)", st.session_state.ai_report.encode('utf-8'), f"AI_Report_{selected_file.replace('.csv', '.md')}", "text/markdown")

def render_incident_response():
    """페이지 4: 사고 대응"""
    st.header("🚨 사고 대응")
    st.markdown("---")

    BLACKLIST_FILE = os.path.join(BASE_DIR, "blacklist.txt")

    def read_blacklist():
        if not os.path.exists(BLACKLIST_FILE): return []
        with open(BLACKLIST_FILE, "r") as f: return [line.strip() for line in f.readlines()]

    def add_to_blacklist(ip):
        with open(BLACKLIST_FILE, "a") as f: f.write(f"{ip}\n")

    def run_simulated_action(action_name, steps):
        progress_bar = st.progress(0)
        status_text = st.empty()
        for i, step in enumerate(steps):
            status_text.info(f"⏳ {step}...")
            time.sleep(np.random.uniform(0.5, 1.5))
            progress_bar.progress((i + 1) / len(steps))
        status_text.success(f"✅ '{action_name}' 조치 완료!")
        progress_bar.empty()

    if 'incident' not in st.session_state or not st.session_state.incident:
        st.info("탐지된 사고가 없습니다. '실시간 보안 관제' 페이지에서 위협이 탐지되면 이 곳으로 이동됩니다.")
        st.stop()

    incident = st.session_state.incident
    st.subheader("🔥 현재 대응 중인 위협")
    
    c1, c2 = st.columns([1,1])
    with c1:
        st.error(f"**공격 유형:** {incident['attack_type']}")
        st.warning(f"**탐지 확신도:** {incident['confidence']:.2%}")
        st.info(f"**출발지 IP:** {incident['source_ip']}")
        st.info(f"**목적지 IP:** {incident['destination_ip']}")
    with c2:
        st.code(incident['log_text'], language='text')

    st.markdown("---")
    st.subheader("🚫 IP 블랙리스트 관리")
    blacklist = read_blacklist()
    
    with st.expander("현재 블랙리스트 보기"):
        st.dataframe(blacklist, use_container_width=True, hide_index=True, column_config={"value": "차단된 IP"}) if blacklist else st.write("블랙리스트에 등록된 IP가 없습니다.")

    ip_to_block = incident.get('source_ip', 'N/A')
    if ip_to_block != "N/A":
        if ip_to_block in blacklist:
            st.warning(f"IP `{ip_to_block}`는 이미 블랙리스트에 존재합니다.")
        elif st.button(f"'{ip_to_block}'를 블랙리스트에 추가", key="add_to_blacklist"):
            add_to_blacklist(ip_to_block)
            st.success(f"IP `{ip_to_block}`를 블랙리스트에 추가했습니다.")
            st.rerun()
    
    st.markdown("---")
    st.subheader("🛠️ 대응 조치 수행 (시뮬레이션)")
    
    r_c1, r_c2, r_c3 = st.columns(3)
    if r_c1.button("🔗 네트워크 격리", use_container_width=True): run_simulated_action("네트워크 격리", ["격리 대상 장치 식별", "네트워크 스위치에 연결", "VLAN 설정 변경", "격리 정책 적용"])
    if r_c2.button("🧱 의심 IP 차단", use_container_width=True): run_simulated_action("IP 차단", ["방화벽 정책 조회", "차단 룰 생성", f"IP '{ip_to_block}'에 대한 차단 룰 적용", "방화벽 정책 업데이트"])
    if r_c3.button("🔄 백업 데이터 복구", use_container_width=True): run_simulated_action("백업 데이터 복구", ["최신 백업 이미지 확인", "백업 스토리지에 연결", "데이터 복원 지점 선택", "시스템 복구 프로세스 시작", "데이터 무결성 검사"])

# --- 4. 메인 애플리케이션 로직 ---
analyzer = load_analyzer()
if analyzer:
    if "page" not in st.session_state:
        st.session_state.page = "실시간 보안 관제"

    with st.sidebar:
        st.title("🚀 V4 통합 보안 대시보드")
        st.markdown("---")
        page_options = {"실시간 보안 관제": "📡", "상세 로그 분석": "🔍", "리포팅 및 인사이트": "📄", "사고 대응": "🚨"}
        
        current_page_index = list(page_options.keys()).index(st.session_state.page)
        choice = st.radio("메뉴를 선택하세요", options=list(page_options.keys()), index=current_page_index, format_func=lambda x: f"{page_options[x]} {x}")

        if choice != st.session_state.page:
            st.session_state.page = choice
            st.rerun()
        
        st.markdown("---")
        st.info(f"**분석 엔진 상태:** ✅ 준비 완료")
        st.metric("로드된 벡터 수", f"{analyzer.vectordb.index.ntotal:,} 개")
        st.markdown("---")

    page_to_render = st.session_state.page
    if page_to_render == "실시간 보안 관제":
        render_realtime_soc_dashboard()
    elif page_to_render == "상세 로그 분석":
        render_detailed_log_analysis()
    elif page_to_render == "리포팅 및 인사이트":
        render_reporting_and_insights()
    elif page_to_render == "사고 대응":
        render_incident_response()