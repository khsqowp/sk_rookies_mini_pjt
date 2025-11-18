"""
V4 통합 보안 대시보드 (통합 Watcher)
- watcher.py의 로직을 Streamlit 앱 내부에 통합한 버전
- 별도 프로세스 없이, 백그라운드 스레드로 파일 시스템을 감시
"""
import streamlit as st
import pandas as pd
import numpy as np
import os
import time
from datetime import datetime
import traceback
from pathlib import Path
import json
import queue
import threading

# Watchdog 관련 임포트
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# .env 파일에서 환경 변수 로드
from dotenv import load_dotenv
load_dotenv()

# 분석 모듈 임포트
from ransomware_model import RansomwareModel
from feature_extractor import extract_pe_header_features

# --- 1. 페이지 및 기본 설정 ---
st.set_page_config(
    page_title="V4 통합 보안 대시보드",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. 전역 변수 및 캐시 설정 ---
BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
DOWNLOAD_DIR = Path.home() / "Downloads"
ANALYSIS_EXTENSIONS = {".exe", ".dll"}
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

class WatcherEventHandler(FileSystemEventHandler):
    """파일 시스템 이벤트를 감지하여 큐에 넣는 핸들러"""
    def __init__(self, file_queue: queue.Queue):
        super().__init__()
        self.file_queue = file_queue

    def on_created(self, event):
        if not event.is_directory:
            self.file_queue.put(Path(event.src_path))

    def on_moved(self, event):
        if not event.is_directory:
            self.file_queue.put(Path(event.dest_path))

def _wait_until_download_complete(path: Path, timeout: float = 10.0):
    """파일 크기가 더 이상 변하지 않을 때까지 대기"""
    last_size = -1
    stable_count = 0
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            current_size = path.stat().st_size
            if current_size > 0 and current_size == last_size:
                stable_count += 1
                if stable_count >= 3:
                    return True
            else:
                stable_count = 0
            last_size = current_size
            time.sleep(0.5)
        except FileNotFoundError:
            time.sleep(0.5)
    return False

def handle_action(file_path: Path, model_result: dict, **kwargs):
    """분석 결과를 로그 파일에 기록"""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "file_name": file_path.name,
        "file_path": str(file_path),
        "label": model_result.get("label"),
        "probability": model_result.get("prob_ransom"),
        "anomalies": model_result.get("anomalies", []),
        "action": "log",
        "action_result": "success"
    }
    
    log_file = LOGS_DIR / "events.jsonl"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    
    return log_entry

@st.cache_resource
def start_watcher_service():
    """Watchdog 옵저버를 별도 스레드에서 시작하고 큐를 반환"""
    file_queue = queue.Queue()
    event_handler = WatcherEventHandler(file_queue)
    observer = Observer()
    observer.schedule(event_handler, str(DOWNLOAD_DIR), recursive=False)
    
    thread = threading.Thread(target=observer.start, daemon=True)
    thread.start()
    
    return observer, file_queue

# --- 4. 페이지 렌더링 함수 ---

def render_realtime_soc_dashboard():
    """페이지 1: 실시간 보안 관제 대시보드 (통합 Watcher)"""
    st.header("📡 실시간 보안 관제")
    st.markdown("---")

    # 세션 상태 초기화
    if 'monitoring_started' not in st.session_state:
        st.session_state.monitoring_started = False
    if 'last_analysis_result' not in st.session_state:
        st.session_state.last_analysis_result = None

    # "관제 시작" 버튼
    if not st.session_state.monitoring_started:
        if st.button("▶️ 관제 시작", type="primary", use_container_width=True):
            st.session_state.monitoring_started = True
            st.rerun()
        st.info(f"'{DOWNLOAD_DIR}' 폴더를 실시간으로 감시하려면 '관제 시작' 버튼을 누르세요.")
        return

    # --- 관제 시작 후 UI ---
    observer, file_queue = start_watcher_service()

    # 모니터링 시작 시 토스트 메시지를 한 번만 표시
    if 'monitoring_toast_shown' not in st.session_state:
        st.toast(f"다운로드 폴더 감시 시작: {DOWNLOAD_DIR}", icon="👀")
        st.session_state.monitoring_toast_shown = True

    st.success(f"✅ **감시 중:** '{DOWNLOAD_DIR}' 폴더에 새로 생성되는 파일을 실시간으로 분석합니다.")
    
    # 큐에서 파일 경로 확인 및 분석 (개선된 루프)
    files_processed = False
    try:
        while True:
            file_path = file_queue.get_nowait()
            files_processed = True
            
            if file_path.suffix.lower() not in ANALYSIS_EXTENSIONS:
                st.toast(f"분석 대상 아님 (무시): {file_path.name}", icon="🤷")
                continue

            with st.container():
                st.info(f"'{file_path.name}' 파일 분석 중...")
                progress_text = st.empty()
                progress_bar = st.progress(0)

                if not _wait_until_download_complete(file_path):
                    st.warning(f"'{file_path.name}' 파일이 안정화되지 않아 분석을 건너뜁니다.")
                    progress_bar.empty()
                    progress_text.empty()
                    continue
                
                try:
                    progress_text.text("1/3: 피처 추출 중...")
                    features = extract_pe_header_features(file_path)
                    progress_bar.progress(33)

                    progress_text.text("2/3: 모델 예측 중...")
                    result = ransomware_model.predict_with_explanation(features)
                    progress_bar.progress(66)
                    
                    st.session_state.last_analysis_result = {
                        "file_name": file_path.name,
                        "result": result
                    }
                    
                    progress_text.text("3/3: 로그 기록 중...")
                    handle_action(
                        file_path=file_path,
                        model_result=result
                    )
                    progress_bar.progress(100)
                    
                    # 완료 후 정리
                    progress_bar.empty()
                    progress_text.empty()
                    st.success(f"✅ '{file_path.name}' 분석 완료!")
                    time.sleep(1) # 메시지 확인 시간

                except Exception as e:
                    progress_bar.empty()
                    progress_text.empty()
                    st.error(f"❌ '{file_path.name}' 분석 중 오류 발생:")
                    st.code(traceback.format_exc())

    except queue.Empty:
        # 큐가 비었을 때 루프 종료
        pass

    # 하나 이상의 파일을 처리했다면 UI를 즉시 새로고침
    if files_processed:
        st.rerun()

    # 최신 분석 결과 표시
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
    else:
        st.info("아직 기록된 탐지 로그가 없습니다.")

    # 1초마다 UI를 새로고침하여 큐를 계속 확인
    time.sleep(1)
    st.rerun()

def render_incident_response():
    """페이지 2: 사고 대응"""
    st.header("🚨 사고 대응")
    st.info("이 페이지는 현재 개발 중입니다.")

# --- 5. 메인 애플리케이션 로직 ---
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
    
    choice = st.radio("메뉴를 선택하세요", options=list(page_options.keys()), format_func=lambda x: f"{page_options[x]} {x}")

    if choice != st.session_state.page:
        st.session_state.page = choice
        st.rerun()
    
    st.markdown("---")
    if ransomware_model:
        st.info(f"**랜섬웨어 분석 엔진:** ✅ 준비 완료")
    else:
        st.error(f"**랜섬웨어 분석 엔진:** ❌ 로드 실패")
    st.markdown("---")

# 페이지 렌더링
if st.session_state.page == "실시간 보안 관제":
    if ransomware_model:
        render_realtime_soc_dashboard()
    else:
        st.error("랜섬웨어 분석 엔진이 로드되지 않아 이 페이지를 표시할 수 없습니다.")
elif st.session_state.page == "사고 대응":
    render_incident_response()