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
import traceback
from pathlib import Path
import json
import queue
import threading

# Watchdog 관련 임포트
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# .env 파일에서 환경 변수 로드
load_dotenv()

# 랜섬웨어 분석 모듈 임포트
from ransomware_model import RansomwareModel
from feature_extractor import extract_features_from_file
from action_handler import handle_action

# --- 1. 페이지 및 기본 설정 ---
st.set_page_config(
    page_title="V4 통합 보안 대시보드",
    page_icon="🚀",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. 전역 변수 및 캐시 설정 ---
BASE_DIR = Path(__file__).resolve().parent
CSV_DIR = BASE_DIR / "CSV Files"
OUTPUT_DIR = BASE_DIR / "output_analysis"
LOGS_DIR = BASE_DIR / "logs"
DOWNLOAD_DIR = Path.home() / "Downloads"
ANALYSIS_EXTENSIONS = {".exe", ".dll", ".zip", ".rar", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".js", ".vbs"}
TEMP_EXTENSIONS = {".tmp", ".crdownload", ".part"}
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)


@st.cache_resource
def load_ransomware_model():
    """랜섬웨어 탐지 모델 로드 (캐싱)"""
    try:
        return RansomwareModel()
    except Exception as e:
        st.error(f"❌ 랜섬웨어 모델 로드 실패: {e}")
        st.warning("모델 파일('models/ransom_model.pkl')이 있는지 확인하세요.")
        return None

# --- 3. Watchdog 및 실시간 분석 관련 헬퍼 ---

def wait_for_complete_download(path: Path, retries: int = 10, interval: float = 1.0) -> bool:
    """파일 크기가 더 이상 변하지 않을 때까지 기다림."""
    last_size = -1
    for _ in range(retries):
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            time.sleep(interval)
            continue
        if size > 0 and size == last_size:
            return True
        last_size = size
        time.sleep(interval)
    return False

class WatcherEventHandler(FileSystemEventHandler):
    """파일 시스템 이벤트를 감지하여 큐에 넣는 핸들러"""
    def __init__(self, file_queue: queue.Queue):
        super().__init__()
        self.file_queue = file_queue
        print("[Watcher] 이벤트 핸들러가 초기화되었습니다.")

    def on_created(self, event):
        if not event.is_directory:
            print(f"[Watcher] 'on_created' 이벤트 감지: {event.src_path}")
            self.file_queue.put(Path(event.src_path))

    def on_moved(self, event):
        if not event.is_directory:
            print(f"[Watcher] 'on_moved' 이벤트 감지: {event.dest_path}")
            self.file_queue.put(Path(event.dest_path))

@st.cache_resource
def start_watcher_service():
    """Watchdog 옵저버를 별도 스레드에서 시작하고 큐를 반환"""
    file_queue = queue.Queue()
    event_handler = WatcherEventHandler(file_queue)
    observer = Observer()
    observer.schedule(event_handler, str(DOWNLOAD_DIR), recursive=False)
    
    # 옵저버를 데몬 스레드에서 실행
    thread = threading.Thread(target=observer.start, daemon=True)
    thread.start()
    
    return observer, file_queue

# --- 4. 페이지 렌더링 함수 ---

def render_realtime_soc_dashboard():
    """페이지 1: 실시간 보안 관제 대시보드 (Watchdog 기반)"""
    st.header("📡 실시간 보안 관제")
    st.markdown("---")

    # 세션 상태 초기화
    if 'monitoring_started' not in st.session_state:
        st.session_state.monitoring_started = False
    if 'last_analysis_result' not in st.session_state:
        st.session_state.last_analysis_result = None

    # "관제 시작" 버튼
    if not st.session_state.monitoring_started:
        if st.button("관제 시작", type="primary", use_container_width=True):
            st.session_state.monitoring_started = True
            st.rerun()
        st.info(f"'{DOWNLOAD_DIR}' 폴더를 실시간으로 감시하려면 '관제 시작' 버튼을 누르세요.")
        return

    # --- 관제 시작 후 UI ---
    # 관제가 시작되면, 캐시된 watcher 서비스/큐를 가져옴
    st.session_state.observer, st.session_state.file_queue = start_watcher_service()

    # 모니터링 시작 시 토스트 메시지를 한 번만 표시
    if 'monitoring_toast_shown' not in st.session_state:
        st.toast(f"다운로드 폴더 감시 시작: {DOWNLOAD_DIR}", icon="👀")
        st.session_state.monitoring_toast_shown = True
    
    st.success(f"✅ **감시 중:** '{DOWNLOAD_DIR}' 폴더에 새로 생성되는 파일을 실시간으로 분석합니다.")
    
    analysis_placeholder = st.container()
    log_placeholder = st.container()

    # 큐에서 파일 경로 확인 및 분석
    # 큐가 빌 때까지 모든 이벤트를 한 번에 처리
    rerun_needed = False
    try:
        while True:
            file_path = st.session_state.file_queue.get_nowait()
            rerun_needed = True # 큐에 항목이 있었으므로 처리가 끝나면 UI 갱신 필요
            
            # 임시 파일 및 분석 대상 아닌 파일 필터링
            if file_path.suffix.lower() in TEMP_EXTENSIONS:
                st.toast(f"임시 파일 감지 (무시): {file_path.name}", icon="💨")
                continue
            elif file_path.suffix.lower() not in ANALYSIS_EXTENSIONS:
                st.toast(f"분석 대상 아님 (무시): {file_path.name}", icon="🤷")
                continue
            
            # 분석 대상 파일 처리
            with st.spinner(f"'{file_path.name}' 파일 분석 중..."):
                if not wait_for_complete_download(file_path):
                    st.warning(f"'{file_path.name}' 파일이 안정화되지 않아 분석을 건너뜁니다.")
                else:
                    try:
                        features = extract_features_from_file(file_path)
                        result = ransomware_model.predict_with_explanation(features)
                        
                        st.session_state.last_analysis_result = {
                            "file_name": file_path.name,
                            "result": result
                        }
                        
                        handle_action(
                            file_path=file_path,
                            features=features,
                            model_result=result,
                            anomalies=result.get("anomalies", []),
                            action="log"
                        )
                        st.success(f"✅ '{file_path.name}' 분석 완료!")
                    except Exception as e:
                        st.error(f"❌ '{file_path.name}' 분석 중 오류 발생: {e}")
                        st.code(traceback.format_exc())

    except queue.Empty:
        # 큐가 비어있으면 루프 종료
        pass

    if rerun_needed:
        st.rerun()

    # 최신 분석 결과 표시
    with analysis_placeholder:
        if st.session_state.last_analysis_result:
            analysis = st.session_state.last_analysis_result
            result = analysis['result']
            label = result['label']
            prob = result['prob_ransom']
            anomalies = result['anomalies']

            st.subheader(f"📜 최신 분석 결과: '{analysis['file_name']}'")
            
            if label == 1:
                st.error(f"**🚨 랜섬웨어 의심 (확률: {prob:.2%})**")
            else:
                st.success(f"**✅ 정상 파일로 판단 (랜섬웨어 확률: {prob:.2%})**")

            if anomalies:
                st.warning("주요 이상 징후:")
                for anom in anomalies:
                    st.markdown(f"- **{anom['description']}** (`{anom['feature']}`: `{anom['value']:.2f}`)")
            st.markdown("---")

    # 로그 뷰어 표시
    with log_placeholder:
        st.subheader("📂 전체 탐지 로그")
        log_file_path = LOGS_DIR / "events.jsonl"
        if log_file_path.exists() and log_file_path.stat().st_size > 0:
            try:
                log_lines = log_file_path.read_text(encoding="utf-8").strip().split('\n')
                log_rows = [json.loads(line) for line in log_lines]
                log_df = pd.DataFrame(log_rows).sort_values("timestamp", ascending=False)
                st.dataframe(log_df, use_container_width=True)
            except (json.JSONDecodeError, FileNotFoundError, ValueError) as e:
                st.warning(f"로그 파일을 읽는 중 오류 발생: {e}")
                st.info("아직 기록된 탐지 로그가 없습니다.")
        else:
            st.info("아직 기록된 탐지 로그가 없습니다.")

    # 1초마다 UI를 새로고침하여 큐를 계속 확인
    time.sleep(1)
    st.rerun()

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
ransomware_model = load_ransomware_model()

if "page" not in st.session_state:
    st.session_state.page = "실시간 보안 관제"

with st.sidebar:
    st.title("🚀 V4 통합 보안 대시보드")
    st.markdown("---")
    page_options = {
        "실시간 보안 관제": "📡",
        "사고 대응": "🚨"
    }
    
    # 현재 페이지 선택
    if st.session_state.page not in page_options:
        st.session_state.page = "실시간 보안 관제"
        
    current_page_index = list(page_options.keys()).index(st.session_state.page)
    choice = st.radio("메뉴를 선택하세요", options=list(page_options.keys()), index=current_page_index, format_func=lambda x: f"{page_options[x]} {x}")

    if choice != st.session_state.page:
        st.session_state.page = choice
        st.rerun()
    
    st.markdown("---")
    if ransomware_model:
        st.info(f"**랜섬웨어 분석 엔진:** ✅ 준비 완료")
    else:
        st.info(f"**랜섬웨어 분석 엔진:** ❌ 로드 실패")
    st.markdown("---")

# 페이지 렌더링
page_to_render = st.session_state.page
if page_to_render == "실시간 보안 관제":
    if ransomware_model:
        render_realtime_soc_dashboard()
    else:
        st.error("랜섬웨어 분석 엔진이 로드되지 않아 이 페이지를 표시할 수 없습니다.")
elif page_to_render == "사고 대응":
    render_incident_response()