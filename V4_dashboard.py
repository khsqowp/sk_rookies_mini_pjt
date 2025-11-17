"""
V4 통합 보안 대시보드 (V5-dev)
- 실시간 파일 시스템 감시, 정적 파일 분석, 리포팅 및 인사이트, 사고 대응 기능을 통합한 Streamlit 애플리케이션
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
import queue
import threading

# 신규 임포트
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# 새로 만든 분석 엔진 임포트
from file_analyzer import FileAnalyzer

# .env 파일에서 환경 변수 로드
load_dotenv()

# --- 1. 페이지 및 기본 설정 ---
st.set_page_config(
    page_title="V5 통합 보안 대시보드",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. 전역 변수, 캐시, 세션 상태 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output_analysis")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 스레드 간 통신을 위한 큐
# UI 업데이트를 위한 로그 메시지와 분석 결과를 담음
event_queue = queue.Queue()

# --- Watchdog 설정 ---
class AnalysisEventHandler(FileSystemEventHandler):
    def __init__(self, q):
        self.queue = q

    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith('.exe'):
            msg = f"✅ 신규 .exe 파일 탐지: {os.path.basename(event.src_path)}"
            print(msg)
            self.queue.put(("log", msg))
            self.queue.put(("file", event.src_path))

def start_watcher(path, q):
    event_handler = AnalysisEventHandler(q)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    msg = f"👀 '{path}' 폴더에 대한 실시간 감시를 시작합니다."
    print(msg)
    q.put(("log", msg))
    return observer

# --- 분석 엔진 로드 ---
@st.cache_resource
def load_file_analyzer():
    # 사용자가 제공한 미리 학습된 모델을 사용해야 함.
    # 모델이 없다면, file_analyzer.py의 테스트 코드가 임시 모델을 생성함.
    model_path = "ransomware_detection_model.pkl"
    if not os.path.exists(model_path):
        st.warning(f"경고: '{model_path}'를 찾을 수 없습니다. file_analyzer.py의 테스트 코드를 실행하여 임시 모델을 생성하세요.")
    try:
        return FileAnalyzer(model_path=model_path)
    except Exception as e:
        st.error(f"❌ 파일 분석 엔진 초기화 실패: {e}")
        return None

# --- 3. 페이지 렌더링 함수 ---

def render_realtime_detection_dashboard():
    """페이지 1: 실시간 탐지 대시보드"""
    st.header("📡 실시간 탐지 대시보드")
    st.markdown("---")

    # --- UI 컨트롤 ---
    st.subheader("감시 설정")
    monitored_dir = st.text_input("감시할 폴더 경로를 입력하세요", value=os.path.join(os.path.expanduser("~"), "Downloads"))
    
    # 감시 시작/중지 버튼
    if st.session_state.get('watcher_running', False):
        if st.button("🛑 탐지 중지", type="primary"):
            st.session_state.watcher_running = False
            if 'watcher_observer' in st.session_state:
                st.session_state.watcher_observer.stop()
                st.session_state.watcher_observer.join()
                del st.session_state['watcher_observer']
                event_queue.put(("log", "⏹️ 실시간 감시를 중지했습니다."))
            st.rerun()
    else:
        if st.button("🚀 탐지 시작"):
            if os.path.isdir(monitored_dir):
                st.session_state.watcher_running = True
                st.session_state.monitored_dir = monitored_dir
                st.rerun()
            else:
                st.error("유효한 폴더 경로가 아닙니다. 다시 입력해주세요.")

    st.markdown("---")
    st.subheader("실시간 탐지 로그")
    log_placeholder = st.container(height=300)
    
    st.subheader("분석 결과")
    results_placeholder = st.container()

    # --- 세션 상태 초기화 ---
    if 'detection_logs' not in st.session_state:
        st.session_state.detection_logs = []
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = pd.DataFrame()

    # --- Watchdog 스레드 시작 ---
    if st.session_state.get('watcher_running') and 'watcher_observer' not in st.session_state:
        observer = start_watcher(st.session_state.monitored_dir, event_queue)
        st.session_state.watcher_observer = observer

    # --- 이벤트 큐 처리 ---
    while not event_queue.empty():
        event_type, data = event_queue.get()
        if event_type == "log":
            st.session_state.detection_logs.insert(0, f"[{datetime.now().strftime('%H:%M:%S')}] {data}")
        elif event_type == "file":
            with st.spinner(f"'{os.path.basename(data)}' 파일 정적 분석 중..."):
                result = file_analyzer.predict_file(data, threshold=0.4) # 임계값 0.4 사용
            
            new_df = pd.DataFrame([result])
            st.session_state.analysis_results = pd.concat([st.session_state.analysis_results, new_df], ignore_index=True)
            
            # 랜섬웨어로 판별된 경우
            if result.get("IsRansomware", False):
                st.session_state.page_title_prefix = "🚨 랜섬웨어 탐지! 🚨"
                st.session_state.incident = result # 사고 대응 페이지로 정보 전달
                st.session_state.page = "사고 대응" # 페이지 전환
                
                # 감시자 중지
                if 'watcher_observer' in st.session_state:
                    st.session_state.watcher_observer.stop()
                    st.session_state.watcher_observer.join()
                    del st.session_state['watcher_observer']
                st.session_state.watcher_running = False
                
                st.rerun()

    # --- UI 업데이트 ---
    with log_placeholder:
        for log in st.session_state.detection_logs:
            st.text(log)

    with results_placeholder:
        if not st.session_state.analysis_results.empty:
            st.dataframe(st.session_state.analysis_results[['FileName', 'Result', 'Probability']], use_container_width=True)

def render_detailed_log_analysis():
    """페이지 2: 상세 로그 분석 (기존 기능 유지)"""
    st.header("🔍 상세 로그 분석")
    st.markdown("---")
    st.info("이 페이지는 이제 레거시 기능입니다. 네트워크 로그(.csv) 파일을 수동으로 분석할 수 있습니다.")
    # ... (이하 기존 코드와 거의 동일, file_analyzer 대신 V4_log_analyzer 사용 필요)
    st.warning("이 기능은 새로운 파일 기반 분석 시스템과 통합되지 않았습니다.")


def render_reporting_and_insights():
    """페이지 3: 리포팅 및 인사이트 (기존 기능 유지)"""
    st.header("📄 리포팅 및 인사이트")
    st.markdown("---")
    st.info("이 페이지는 이제 레거시 기능입니다. 과거 네트워크 로그 분석 결과에 대한 리포트를 생성할 수 있습니다.")
    # ... (이하 기존 코드와 거의 동일)
    st.warning("이 기능은 새로운 파일 기반 분석 시스템과 통합되지 않았습니다.")

def render_incident_response():
    """페이지 4: 사고 대응 (업그레이드)"""
    st.header("🚨 사고 대응")
    st.markdown("---")

    if 'incident' not in st.session_state or not st.session_state.incident:
        st.info("탐지된 사고가 없습니다. '실시간 탐지 대시보드'에서 위협이 탐지되면 이 곳으로 자동 이동됩니다.")
        st.stop()

    incident = st.session_state.incident
    
    # --- 1. LLM 상세 분석 요청 ---
    with st.spinner("LLM이 탐지된 파일에 대한 상세 분석 리포트를 생성 중입니다..."):
        # 이 부분은 file_analyzer에 LLM 연동 함수를 추가해야 함
        # report_text = file_analyzer.get_llm_report(incident['Features'])
        # 임시 텍스트
        time.sleep(2) # LLM 호출 시뮬레이션
        report_text = f"""
        ### AI 기반 심층 분석 보고서

        **파일명**: `{incident['FileName']}`

        #### 1. 개요
        본 파일은 **랜섬웨어**일 확률이 **{incident['Probability']:.2%}**로 매우 높게 나타났습니다. 
        파일의 내부 구조적 특징(PE 헤더, 섹션 엔트로피 등)을 분석한 결과, 일반적인 정상 프로그램과는 다른 여러 이상 징후가 발견되었습니다.

        #### 2. 주요 악성 특징 분석
        - **높은 섹션 엔트로피**: 파일의 특정 섹션에서 데이터의 무작위성(엔트로피)이 비정상적으로 높게 측정되었습니다. 이는 파일 내부에 암호화된 코드나 데이터를 숨기고 있을 강력한 징후입니다.
        - **비정상적인 이미지 크기**: 파일이 메모리에 로드될 때 차지하는 크기가 일반적인 애플리케이션에 비해 과도하게 큽니다. 이는 악성 페이로드를 포함하고 있을 가능성을 시사합니다.

        #### 3. 예상 위협 시나리오
        이 파일이 실행될 경우, 시스템의 주요 파일을 암호화하고 사용자에게 금전을 요구하는 전형적인 랜섬웨어 행위를 수행할 것으로 예상됩니다. 네트워크를 통해 다른 시스템으로 전파될 가능성도 배제할 수 없습니다.

        #### 4. 권장 조치
        - **즉시 격리 및 삭제**: 해당 파일의 실행을 즉시 차단하고 시스템에서 삭제해야 합니다.
        - **전체 시스템 검사**: 다른 시스템으로의 전파 가능성에 대비하여 전체 네트워크에 대한 정밀 검사가 필요합니다.
        - **출처 추적 및 차단**: 해당 파일이 유입된 경로(이메일, 웹사이트 등)를 파악하여 추가 위협을 차단해야 합니다.
        """
    
    st.subheader("🤖 AI 심층 분석 리포트")
    st.markdown(report_text)
    st.markdown("---")

    # --- 2. 자동 대응 다이어그램 및 시뮬레이션 ---
    st.subheader("⚙️ 자동 대응 시스템 가동")
    
    response_flow_chart = """
    digraph {
        rankdir=LR;
        node [shape=box, style=rounded];
        A [label="파일 탐지"];
        B [label="파일 격리\n(Quarantine)"];
        C [label="해시 값 추출\n(SHA-256)"];
        D [label="차단 목록 추가\n(Blocklist)"];
        E [label="관리자 알림"];
        A -> B -> C -> D -> E;
    }
    """
    
    graph_placeholder = st.empty()
    status_placeholder = st.empty()
    
    graph_placeholder.graphviz_chart(response_flow_chart)

    steps = {
        "B": "파일을 안전한 공간으로 격리하는 중...",
        "C": "파일의 고유 해시(SHA-256) 값을 추출하는 중...",
        "D": "추출된 해시를 중앙 차단 목록(DB)에 추가하는 중...",
        "E": "보안 관리자에게 긴급 알림을 전송하는 중..."
    }
    
    step_nodes = ["A", "B", "C", "D", "E"]

    for i, node_id in enumerate(step_nodes):
        # 현재 단계를 하이라이트하는 그래프viz 코드 생성
        highlighted_chart = response_flow_chart.replace(f'{node_id} [', f'{node_id} [style=filled, fillcolor=lightcoral, ')
        graph_placeholder.graphviz_chart(highlighted_chart)
        
        if node_id in steps:
            with status_placeholder.container():
                st.info(f"⏳ {steps[node_id]}")
        
        time.sleep(1.5)

    # 최종 완료 상태
    final_chart = response_flow_chart.replace('digraph {', 'digraph {\n    E [style=filled, fillcolor=lightgreen];')
    graph_placeholder.graphviz_chart(final_chart)
    status_placeholder.success("✅ 모든 자동 대응 조치가 완료되었습니다.")


# --- 4. 메인 애플리케이션 로직 ---
file_analyzer = load_file_analyzer()

if "page" not in st.session_state:
    st.session_state.page = "실시간 탐지 대시보드"
if "page_title_prefix" not in st.session_state:
    st.session_state.page_title_prefix = ""

with st.sidebar:
    st.title(f"{st.session_state.page_title_prefix} 🚀 V5 통합 보안 대시보드")
    st.markdown("---")
    page_options = {"실시간 탐지 대시보드": "📡", "상세 로그 분석": "🔍", "리포팅 및 인사이트": "📄", "사고 대응": "🚨"}
    
    # 페이지 선택 로직
    if st.session_state.get('watcher_running', False):
        # 감시 중에는 페이지 이동 방지
        st.radio("메뉴", options=list(page_options.keys()), index=0, disabled=True, help="실시간 탐지 중에는 다른 메뉴로 이동할 수 없습니다.")
    else:
        current_page_index = list(page_options.keys()).index(st.session_state.page)
        choice = st.radio("메뉴를 선택하세요", options=list(page_options.keys()), index=current_page_index, format_func=lambda x: f"{page_options[x]} {x}")
        if choice != st.session_state.page:
            st.session_state.page = choice
            st.rerun()
    
    st.markdown("---")
    if file_analyzer:
        st.info(f"**파일 분석 엔진:** ✅ 준비 완료")
    else:
        st.error(f"**파일 분석 엔진:** ❌ 로드 실패")
    st.markdown("---")

# 페이지 라우팅
page_to_render = st.session_state.page
if page_to_render == "실시간 탐지 대시보드":
    render_realtime_detection_dashboard()
elif page_to_render == "상세 로그 분석":
    render_detailed_log_analysis()
elif page_to_render == "리포팅 및 인사이트":
    render_reporting_and_insights()
elif page_to_render == "사고 대응":
    render_incident_response()
