"""
V4 통합 보안 대시보드 (Enhanced Version)
- 실시간 보안 관제 대시보드 강화
- 사고 대응 탭 구현
- 보고서 자동 생성 시스템 (일간/주간/월간/사고)
"""
import streamlit as st
import pandas as pd
import numpy as np
import os
import time
from datetime import datetime, timedelta
import traceback
from pathlib import Path
import json
import queue
import threading
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import openai

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
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. 전역 변수 및 캐시 설정 ---
BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"
DOWNLOAD_DIR = Path.home() / "Downloads"
ANALYSIS_EXTENSIONS = {".exe", ".dll"}

# 디렉토리 생성
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR / "daily", exist_ok=True)
os.makedirs(REPORTS_DIR / "weekly", exist_ok=True)
os.makedirs(REPORTS_DIR / "monthly", exist_ok=True)
os.makedirs(REPORTS_DIR / "incidents", exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# --- 3. AI 요약 기능 ---
@st.cache_data(ttl=300)
def get_ai_summary(analysis_result: dict) -> str:
    """OpenAI API를 사용하여 분석 결과를 요약합니다."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "⚠️ OpenAI API 키가 설정되지 않았습니다. .env 파일에 키를 추가해주세요."

    client = openai.OpenAI(api_key=api_key)

    file_name = analysis_result['file_name']
    result = analysis_result['result']
    label = "랜섬웨어" if result['label'] == 1 else "정상 파일"
    prob = result['prob_ransom']
    anomalies = result['anomalies']

    # 프롬프트 생성
    prompt = f"""
당신은 최고의 사이버 보안 분석가입니다. 아래의 랜섬웨어 탐지 시스템 분석 결과를 보고, 보안 관제 담당자가 즉시 상황을 파악하고 조치할 수 있도록 핵심 내용을 요약하고 명확한 권고 사항을 제시해주세요.

**분석 대상 파일:** `{file_name}`

**[분석 결과]**
- **판정:** {label}
- **랜섬웨어일 확률:** {prob:.2%}

**[판단의 주요 근거 (이상 징후 Top 5)]**
"""
    if not anomalies:
        prompt += "- 특이한 이상 징후가 발견되지 않았습니다.\n"
    else:
        for i, anom in enumerate(anomalies[:5], 1):
            prompt += f"- **{i}. {anom['description']} ({anom['feature']})**: 측정값 {anom['value']:.2f} (정상 평균: {anom['mean']:.2f}, Z-Score: {anom['z_score']:.2f})\n"

    prompt += """
---
**[요약 및 권고]** (아래 형식에 맞춰 한글로 작성)
1. **위협 요약:** (위 분석 결과를 바탕으로, 이 파일이 왜 위험한지 또는 안전한지에 대한 핵심 요약)
2. **신뢰도 평가:** (탐지 확률과 이상 징후를 고려하여, 이 분석 결과가 얼마나 신뢰할 수 있는지 평가)
3. **권고 조치:** (보안 담당자가 수행해야 할 다음 행동을 구체적으로 제시)
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "당신은 최고의 사이버 보안 분석가입니다."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.5,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"❌ OpenAI API 호출 중 오류 발생: {e}"

# --- 4. 로그 데이터 로드 함수 ---
@st.cache_data(ttl=5)
def load_events_log():
    """이벤트 로그 파일을 읽어서 DataFrame으로 반환"""
    log_file_path = LOGS_DIR / "events.jsonl"
    if not log_file_path.exists() or log_file_path.stat().st_size == 0:
        return pd.DataFrame()

    try:
        log_lines = log_file_path.read_text(encoding="utf-8").strip().split('\n')
        log_rows = [json.loads(line) for line in log_lines if line.strip()]
        df = pd.DataFrame(log_rows)

        # timestamp를 datetime으로 변환
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df.sort_values('timestamp', ascending=False)
    except Exception as e:
        st.error(f"로그 파일 읽기 오류: {e}")
        return pd.DataFrame()

# --- 5. 대시보드 메트릭 계산 ---
def calculate_dashboard_metrics(df):
    """대시보드 메트릭 계산"""
    if df.empty:
        return {
            'total_events': 0,
            'ransomware_count': 0,
            'benign_count': 0,
            'ransomware_ratio': 0,
            'recent_1h_count': 0,
            'avg_probability': 0
        }

    total_events = len(df)
    ransomware_count = (df['label'] == 1).sum()
    benign_count = (df['label'] == 0).sum()
    ransomware_ratio = ransomware_count / total_events if total_events > 0 else 0

    # 최근 1시간 이벤트 수
    one_hour_ago = datetime.now() - timedelta(hours=1)
    recent_1h_count = (df['timestamp'] >= one_hour_ago).sum()

    # 평균 랜섬웨어 확률
    avg_probability = df['probability'].mean() if 'probability' in df.columns else 0

    return {
        'total_events': total_events,
        'ransomware_count': ransomware_count,
        'benign_count': benign_count,
        'ransomware_ratio': ransomware_ratio,
        'recent_1h_count': recent_1h_count,
        'avg_probability': avg_probability
    }

# --- 6. 차트 생성 함수 ---
def create_timeline_chart(df):
    """시간별 탐지 추이 차트"""
    if df.empty:
        return None

    # 시간별 그룹화
    df_hourly = df.copy()
    df_hourly['hour'] = df_hourly['timestamp'].dt.floor('H')

    hourly_stats = df_hourly.groupby(['hour', 'label']).size().reset_index(name='count')
    hourly_stats['label_name'] = hourly_stats['label'].map({0: '정상', 1: '랜섬웨어'})

    fig = px.line(
        hourly_stats,
        x='hour',
        y='count',
        color='label_name',
        title='시간별 탐지 추이',
        labels={'hour': '시간', 'count': '탐지 수', 'label_name': '분류'},
        color_discrete_map={'정상': '#28a745', '랜섬웨어': '#dc3545'}
    )

    fig.update_layout(
        xaxis_title='시간',
        yaxis_title='탐지 수',
        hovermode='x unified',
        height=400
    )

    return fig

def create_probability_distribution_chart(df):
    """랜섬웨어 확률 분포 차트"""
    if df.empty or 'probability' not in df.columns:
        return None

    fig = px.histogram(
        df,
        x='probability',
        color='label',
        nbins=20,
        title='랜섬웨어 확률 분포',
        labels={'probability': '랜섬웨어 확률', 'label': '분류', 'count': '빈도'},
        color_discrete_map={0: '#28a745', 1: '#dc3545'}
    )

    fig.update_layout(
        xaxis_title='랜섬웨어 확률',
        yaxis_title='빈도',
        height=400,
        showlegend=True
    )

    return fig

def create_risk_gauge_chart(avg_probability):
    """위험도 게이지 차트"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=avg_probability * 100,
        title={'text': "평균 위험도 (%)"},
        delta={'reference': 50},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': "darkred"},
            'steps': [
                {'range': [0, 30], 'color': "#28a745"},
                {'range': [30, 70], 'color': "#ffc107"},
                {'range': [70, 100], 'color': "#dc3545"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 70
            }
        }
    ))

    fig.update_layout(height=300)
    return fig

# --- 7. 모델 로드 ---
@st.cache_resource
def load_ransomware_model():
    """랜섬웨어 탐지 모델 로드 (캐싱)"""
    try:
        return RansomwareModel()
    except Exception as e:
        st.error(f"❌ 랜섬웨어 모델 로드 실패: {e}")
        st.warning("모델 파일('models/ransom_model.pkl')이 있는지 확인하세요.")
        return None

# --- 8. Watchdog 이벤트 핸들러 ---
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

# --- 9. 페이지 1: 실시간 보안 관제 ---
def render_realtime_soc_dashboard():
    """페이지 1: 실시간 보안 관제 대시보드 (강화 버전)"""
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

    st.success(f"✅ **감시 중:** '{DOWNLOAD_DIR}' 폴더")

    # --- 실시간 메트릭 대시보드 ---
    st.subheader("📊 실시간 보안 메트릭")

    # 로그 데이터 로드
    df = load_events_log()
    metrics = calculate_dashboard_metrics(df)

    # 메트릭 카드 (4개 컬럼)
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="총 탐지 수",
            value=f"{metrics['total_events']}건",
            delta=f"+{metrics['recent_1h_count']}건 (1시간)",
            delta_color="normal"
        )

    with col2:
        st.metric(
            label="랜섬웨어 탐지",
            value=f"{metrics['ransomware_count']}건",
            delta=f"{metrics['ransomware_ratio']:.1%}",
            delta_color="inverse"
        )

    with col3:
        st.metric(
            label="정상 파일",
            value=f"{metrics['benign_count']}건",
            delta=f"{(1-metrics['ransomware_ratio']):.1%}",
            delta_color="normal"
        )

    with col4:
        st.metric(
            label="평균 위험도",
            value=f"{metrics['avg_probability']:.2%}",
            delta="실시간",
            delta_color="off"
        )

    st.markdown("---")

    # --- 차트 시각화 (2개 컬럼) ---
    if not df.empty:
        col1, col2 = st.columns(2)

        with col1:
            timeline_chart = create_timeline_chart(df)
            if timeline_chart:
                st.plotly_chart(timeline_chart, use_container_width=True)

        with col2:
            prob_chart = create_probability_distribution_chart(df)
            if prob_chart:
                st.plotly_chart(prob_chart, use_container_width=True)

        # 위험도 게이지
        if metrics['avg_probability'] > 0:
            gauge_chart = create_risk_gauge_chart(metrics['avg_probability'])
            st.plotly_chart(gauge_chart, use_container_width=True)

    st.markdown("---")

    # --- 파일 큐 처리 ---
    files_processed = False
    try:
        while True:
            file_path = file_queue.get_nowait()
            files_processed = True

            if file_path.suffix.lower() not in ANALYSIS_EXTENSIONS:
                st.toast(f"분석 대상 아님 (무시): {file_path.name}", icon="🤷")
                continue

            st.toast(f"'{file_path.name}' 파일 분석 중...", icon="⏱️")

            if not _wait_until_download_complete(file_path):
                st.warning(f"'{file_path.name}' 파일이 안정화되지 않아 분석을 건너뜁니다.")
                continue

            try:
                # 1. 분석 수행
                features = extract_pe_header_features(file_path)
                result = ransomware_model.predict_with_explanation(features)

                analysis_payload = {
                    "file_name": file_path.name,
                    "result": result
                }
                st.session_state.last_analysis_result = analysis_payload

                # 2. 로그 기록
                handle_action(
                    file_path=file_path,
                    model_result=result
                )

                # 3. AI 요약 요청
                st.toast("🤖 AI 애널리스트 브리핑 요청 중...", icon="🧠")
                summary = get_ai_summary(analysis_payload)
                st.session_state.ai_summary = summary

                # 4. 완료 후 토스트 예약
                st.session_state.show_analysis_complete_toast = file_path.name

            except Exception as e:
                st.error(f"❌ '{file_path.name}' 분석 중 오류 발생:")
                st.code(traceback.format_exc())

    except queue.Empty:
        pass

    # 하나 이상의 파일을 처리했다면 UI를 즉시 새로고침
    if files_processed:
        st.rerun()

    # --- 최신 분석 결과 표시 ---
    if st.session_state.last_analysis_result:
        analysis = st.session_state.last_analysis_result
        result = analysis['result']
        label = result['label']
        prob = result['prob_ransom']
        anomalies = result['anomalies']

        st.subheader(f"📜 최신 분석 결과: '{analysis['file_name']}'")

        # AI 요약 표시
        if st.session_state.get("ai_summary"):
            with st.expander("🤖 AI 애널리스트 브리핑 보기", expanded=True):
                st.markdown(st.session_state.ai_summary)

        if label == 1:
            st.error(f"**🚨 랜섬웨어 의심 (확률: {prob:.2%})**")
        else:
            st.success(f"**✅ 정상 파일로 판단 (랜섬웨어 확률: {prob:.2%})**")

        if anomalies:
            st.warning("주요 이상 징후:")
            for anom in anomalies[:5]:
                st.markdown(f"- **{anom['description']}** (`{anom['feature']}`: `{anom['value']:.2f}`)")
        st.markdown("---")

    # --- 전체 탐지 로그 표시 ---
    st.subheader("📂 전체 탐지 로그")
    if not df.empty:
        # 최근 20개만 표시
        st.dataframe(
            df.head(20)[['timestamp', 'file_name', 'label', 'probability', 'action_result']],
            use_container_width=True
        )
    else:
        st.info("아직 기록된 탐지 로그가 없습니다.")

    # 1초마다 UI를 새로고침하여 큐를 계속 확인
    time.sleep(1)
    st.rerun()

# --- 10. 사고 관리 시스템 ---
INCIDENTS_FILE = LOGS_DIR / "incidents.json"

def load_incidents():
    """사고 목록 로드"""
    if not INCIDENTS_FILE.exists():
        return []
    try:
        with open(INCIDENTS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return []

def save_incidents(incidents):
    """사고 목록 저장"""
    with open(INCIDENTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(incidents, f, ensure_ascii=False, indent=2)

def create_incident_from_detection(log_entry):
    """탐지 로그로부터 사고 생성"""
    incident = {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "created_at": datetime.now().isoformat(),
        "file_name": log_entry.get("file_name"),
        "file_path": log_entry.get("file_path"),
        "probability": log_entry.get("probability", 0),
        "status": "탐지됨",  # 탐지됨 → 분석중 → 격리됨 → 복구중 → 완료
        "priority": "높음" if log_entry.get("probability", 0) > 0.7 else "중간",
        "assigned_to": "미지정",
        "timeline": [
            {
                "timestamp": datetime.now().isoformat(),
                "status": "탐지됨",
                "description": f"랜섬웨어 탐지 (확률: {log_entry.get('probability', 0):.2%})"
            }
        ],
        "checklist": [
            {"task": "초기 분석 완료", "completed": False},
            {"task": "영향 범위 파악", "completed": False},
            {"task": "파일 격리/삭제", "completed": False},
            {"task": "시스템 스캔 실시", "completed": False},
            {"task": "백업 복구 확인", "completed": False},
            {"task": "사고 보고서 작성", "completed": False}
        ],
        "notes": []
    }
    return incident

def update_incident_status(incident_id, new_status, description=""):
    """사고 상태 업데이트"""
    incidents = load_incidents()
    for inc in incidents:
        if inc["incident_id"] == incident_id:
            inc["status"] = new_status
            inc["timeline"].append({
                "timestamp": datetime.now().isoformat(),
                "status": new_status,
                "description": description or f"상태 변경: {new_status}"
            })
            break
    save_incidents(incidents)

# --- 11. 페이지 2: 사고 대응 ---
def render_incident_response():
    """페이지 2: 사고 대응"""
    st.header("🚨 사고 대응")
    st.markdown("---")

    # 랜섬웨어 탐지 이벤트를 사고로 자동 등록
    df = load_events_log()
    if not df.empty:
        ransomware_events = df[df['label'] == 1]

        # 기존 사고 목록 로드
        incidents = load_incidents()
        existing_files = {inc['file_name'] for inc in incidents}

        # 새로운 랜섬웨어 탐지를 사고로 등록
        for _, row in ransomware_events.iterrows():
            if row['file_name'] not in existing_files:
                new_incident = create_incident_from_detection(row.to_dict())
                incidents.append(new_incident)

        save_incidents(incidents)

    # 사고 목록 재로드
    incidents = load_incidents()

    # 사고 현황 메트릭
    st.subheader("📊 사고 대응 현황")

    active_incidents = [inc for inc in incidents if inc['status'] != '완료']
    completed_incidents = [inc for inc in incidents if inc['status'] == '완료']
    high_priority = [inc for inc in active_incidents if inc['priority'] == '높음']

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("총 사고", len(incidents))
    with col2:
        st.metric("진행중", len(active_incidents), delta=f"-{len(completed_incidents)} 완료")
    with col3:
        st.metric("높은 우선순위", len(high_priority), delta_color="inverse")
    with col4:
        completion_rate = (len(completed_incidents) / len(incidents) * 100) if incidents else 0
        st.metric("완료율", f"{completion_rate:.1f}%")

    st.markdown("---")

    # 진행중인 사고 목록
    if active_incidents:
        st.subheader("🔥 진행중인 사고")

        for inc in active_incidents:
            with st.expander(f"**{inc['incident_id']}** - {inc['file_name']} ({inc['status']})", expanded=False):
                col1, col2 = st.columns([2, 1])

                with col1:
                    st.markdown(f"**파일명:** `{inc['file_name']}`")
                    st.markdown(f"**경로:** `{inc['file_path']}`")
                    st.markdown(f"**탐지 확률:** {inc['probability']:.2%}")
                    st.markdown(f"**생성 시간:** {inc['created_at']}")

                with col2:
                    # 우선순위 배지
                    priority_color = {"높음": "🔴", "중간": "🟡", "낮음": "🟢"}
                    st.markdown(f"**우선순위:** {priority_color.get(inc['priority'], '')} {inc['priority']}")
                    st.markdown(f"**담당자:** {inc['assigned_to']}")
                    st.markdown(f"**현재 상태:** **{inc['status']}**")

                st.markdown("---")

                # 타임라인
                st.markdown("**📅 사고 타임라인:**")
                for event in reversed(inc['timeline']):
                    timestamp = datetime.fromisoformat(event['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                    st.markdown(f"- **{timestamp}** - {event['status']}: {event['description']}")

                st.markdown("---")

                # 체크리스트
                st.markdown("**✅ 대응 체크리스트:**")
                for i, task in enumerate(inc['checklist']):
                    checked = "☑️" if task['completed'] else "⬜"
                    st.markdown(f"{checked} {task['task']}")

                st.markdown("---")

                # 상태 업데이트
                st.markdown("**🔄 상태 업데이트:**")
                col1, col2, col3 = st.columns(3)

                with col1:
                    if st.button("분석중으로 변경", key=f"analyze_{inc['incident_id']}"):
                        update_incident_status(inc['incident_id'], "분석중", "담당자가 상세 분석 시작")
                        st.rerun()

                with col2:
                    if st.button("격리됨으로 변경", key=f"isolate_{inc['incident_id']}"):
                        update_incident_status(inc['incident_id'], "격리됨", "악성 파일 격리 완료")
                        st.rerun()

                with col3:
                    if st.button("완료로 변경", key=f"complete_{inc['incident_id']}"):
                        update_incident_status(inc['incident_id'], "완료", "사고 대응 완료")
                        st.rerun()

        st.markdown("---")
    else:
        st.info("현재 진행중인 사고가 없습니다.")

    # 완료된 사고 목록
    if completed_incidents:
        st.subheader("✅ 완료된 사고")

        completed_df = pd.DataFrame([
            {
                "사고 ID": inc['incident_id'],
                "파일명": inc['file_name'],
                "생성 시간": inc['created_at'],
                "완료 시간": inc['timeline'][-1]['timestamp'] if inc['timeline'] else "-",
                "우선순위": inc['priority']
            }
            for inc in completed_incidents
        ])

        st.dataframe(completed_df, use_container_width=True)
    else:
        st.info("아직 완료된 사고가 없습니다.")

# --- 12. 보고서 생성 시스템 ---
def generate_daily_report(target_date=None):
    """일간 보고서 생성"""
    if target_date is None:
        target_date = datetime.now().date()
    else:
        target_date = datetime.fromisoformat(target_date).date() if isinstance(target_date, str) else target_date

    date_str = target_date.strftime('%Y-%m-%d')
    report_dir = REPORTS_DIR / "daily" / date_str
    os.makedirs(report_dir, exist_ok=True)

    df = load_events_log()
    if df.empty:
        return None

    # 해당 날짜의 이벤트 필터링
    df['date'] = df['timestamp'].dt.date
    daily_df = df[df['date'] == target_date]

    if daily_df.empty:
        return None

    # 통계 계산
    total_events = len(daily_df)
    ransomware_count = (daily_df['label'] == 1).sum()
    benign_count = (daily_df['label'] == 0).sum()
    avg_prob = daily_df['probability'].mean() if 'probability' in daily_df.columns else 0

    # 보고서 내용 생성
    report_content = f"""# 일간 보안 관제 보고서
**날짜:** {date_str}
**생성 시간:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 1. 요약

- **총 탐지 이벤트:** {total_events}건
- **랜섬웨어 탐지:** {ransomware_count}건
- **정상 파일:** {benign_count}건
- **평균 위험도:** {avg_prob:.2%}

---

## 2. 상세 통계

### 시간대별 탐지 분포
"""

    # 시간대별 통계
    hourly_stats = daily_df.groupby(daily_df['timestamp'].dt.hour).size()
    for hour, count in hourly_stats.items():
        report_content += f"- {hour:02d}:00 ~ {hour:02d}:59: {count}건\n"

    report_content += "\n---\n\n## 3. 랜섬웨어 탐지 상세\n\n"

    if ransomware_count > 0:
        ransomware_events = daily_df[daily_df['label'] == 1]
        for idx, row in ransomware_events.iterrows():
            report_content += f"""### {row['file_name']}
- **경로:** `{row['file_path']}`
- **탐지 시간:** {row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}
- **랜섬웨어 확률:** {row.get('probability', 0):.2%}
- **조치:** {row.get('action_result', 'N/A')}

"""
    else:
        report_content += "금일 랜섬웨어 탐지 없음\n\n"

    report_content += "\n---\n\n## 4. 권고 사항\n\n"

    if ransomware_count > 0:
        report_content += f"- 금일 {ransomware_count}건의 랜섬웨어 의심 파일이 탐지되었습니다.\n"
        report_content += "- 모든 시스템에 대한 전체 스캔을 권장합니다.\n"
        report_content += "- 백업 시스템의 무결성을 확인하세요.\n"
    else:
        report_content += "- 금일 랜섬웨어 탐지가 없었습니다.\n"
        report_content += "- 정기적인 시스템 업데이트를 유지하세요.\n"

    report_content += "\n---\n\n**보고서 종료**"

    # 파일 저장
    report_path = report_dir / f"daily_report_{date_str}.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_content)

    return report_path

def generate_weekly_report(target_week=None):
    """주간 보고서 생성"""
    if target_week is None:
        today = datetime.now()
        week_num = today.isocalendar()[1]
        year = today.year
    else:
        year, week_num = map(int, target_week.split('-W'))

    week_str = f"{year}-W{week_num:02d}"
    report_dir = REPORTS_DIR / "weekly" / week_str
    os.makedirs(report_dir, exist_ok=True)

    df = load_events_log()
    if df.empty:
        return None

    # 해당 주의 이벤트 필터링
    df['week'] = df['timestamp'].dt.isocalendar().week
    df['year'] = df['timestamp'].dt.year
    weekly_df = df[(df['year'] == year) & (df['week'] == week_num)]

    if weekly_df.empty:
        return None

    # 통계 계산
    total_events = len(weekly_df)
    ransomware_count = (weekly_df['label'] == 1).sum()
    benign_count = (weekly_df['label'] == 0).sum()
    avg_prob = weekly_df['probability'].mean() if 'probability' in weekly_df.columns else 0

    # 일별 통계
    daily_stats = weekly_df.groupby(weekly_df['timestamp'].dt.date).agg({
        'label': ['count', lambda x: (x == 1).sum()]
    })

    # 보고서 내용 생성
    report_content = f"""# 주간 보안 관제 보고서
**기간:** {week_str} ({year}년 {week_num}주차)
**생성 시간:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 1. 주간 요약

- **총 탐지 이벤트:** {total_events}건
- **랜섬웨어 탐지:** {ransomware_count}건
- **정상 파일:** {benign_count}건
- **평균 위험도:** {avg_prob:.2%}
- **일평균 탐지:** {total_events / 7:.1f}건

---

## 2. 일별 추이

| 날짜 | 총 탐지 | 랜섬웨어 | 정상 |
|------|---------|----------|------|
"""

    for date_val, row in daily_stats.iterrows():
        total = row[('label', 'count')]
        ransomware = row[('label', '<lambda>')]
        benign = total - ransomware
        report_content += f"| {date_val} | {total} | {ransomware} | {benign} |\n"

    report_content += "\n---\n\n## 3. 주요 위협 분석\n\n"

    if ransomware_count > 0:
        ransomware_events = weekly_df[weekly_df['label'] == 1]
        file_counts = ransomware_events['file_name'].value_counts()
        report_content += "### 가장 많이 탐지된 파일 Top 5\n\n"
        for file_name, count in file_counts.head(5).items():
            report_content += f"- **{file_name}**: {count}건\n"
    else:
        report_content += "주간 랜섬웨어 탐지 없음\n"

    report_content += "\n---\n\n## 4. 주간 권고 사항\n\n"

    if ransomware_count > 5:
        report_content += f"- 이번 주 {ransomware_count}건의 랜섬웨어가 탐지되었습니다. 보안 정책 강화가 필요합니다.\n"
    elif ransomware_count > 0:
        report_content += f"- 이번 주 {ransomware_count}건의 랜섬웨어가 탐지되었습니다. 지속적인 모니터링이 필요합니다.\n"
    else:
        report_content += "- 이번 주 랜섬웨어 탐지가 없었습니다. 우수한 보안 상태입니다.\n"

    report_content += "\n---\n\n**보고서 종료**"

    # 파일 저장
    report_path = report_dir / f"weekly_report_{week_str}.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_content)

    return report_path

def generate_monthly_report(target_month=None):
    """월간 보고서 생성"""
    if target_month is None:
        today = datetime.now()
        year = today.year
        month = today.month
    else:
        year, month = map(int, target_month.split('-'))

    month_str = f"{year}-{month:02d}"
    report_dir = REPORTS_DIR / "monthly" / month_str
    os.makedirs(report_dir, exist_ok=True)

    df = load_events_log()
    if df.empty:
        return None

    # 해당 월의 이벤트 필터링
    df['month'] = df['timestamp'].dt.to_period('M')
    target_period = pd.Period(f"{year}-{month:02d}", freq='M')
    monthly_df = df[df['month'] == target_period]

    if monthly_df.empty:
        return None

    # 통계 계산
    total_events = len(monthly_df)
    ransomware_count = (monthly_df['label'] == 1).sum()
    benign_count = (monthly_df['label'] == 0).sum()
    avg_prob = monthly_df['probability'].mean() if 'probability' in monthly_df.columns else 0

    # 주별 통계
    weekly_stats = monthly_df.groupby(monthly_df['timestamp'].dt.isocalendar().week).agg({
        'label': ['count', lambda x: (x == 1).sum()]
    })

    # 보고서 내용 생성
    report_content = f"""# 월간 보안 관제 보고서
**기간:** {month_str} ({year}년 {month}월)
**생성 시간:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 1. 월간 요약

- **총 탐지 이벤트:** {total_events}건
- **랜섬웨어 탐지:** {ransomware_count}건
- **정상 파일:** {benign_count}건
- **평균 위험도:** {avg_prob:.2%}
- **일평균 탐지:** {total_events / 30:.1f}건

---

## 2. 주별 추이

| 주차 | 총 탐지 | 랜섬웨어 | 정상 |
|------|---------|----------|------|
"""

    for week, row in weekly_stats.iterrows():
        total = row[('label', 'count')]
        ransomware = row[('label', '<lambda>')]
        benign = total - ransomware
        report_content += f"| {week}주차 | {total} | {ransomware} | {benign} |\n"

    report_content += "\n---\n\n## 3. 월간 위협 분석\n\n"

    if ransomware_count > 0:
        ransomware_events = monthly_df[monthly_df['label'] == 1]
        file_counts = ransomware_events['file_name'].value_counts()
        report_content += "### 가장 많이 탐지된 파일 Top 10\n\n"
        for file_name, count in file_counts.head(10).items():
            report_content += f"- **{file_name}**: {count}건\n"

        # 시간대별 분석
        hourly_distribution = ransomware_events.groupby(ransomware_events['timestamp'].dt.hour).size()
        peak_hour = hourly_distribution.idxmax()
        report_content += f"\n### 탐지 피크 시간대\n\n- **{peak_hour:02d}:00 ~ {peak_hour:02d}:59**: 가장 많은 탐지 발생\n"
    else:
        report_content += "월간 랜섬웨어 탐지 없음\n"

    report_content += "\n---\n\n## 4. 월간 권고 사항\n\n"

    if ransomware_count > 10:
        report_content += f"- 이번 달 {ransomware_count}건의 랜섬웨어가 탐지되었습니다. 보안 교육 및 정책 강화가 시급합니다.\n"
    elif ransomware_count > 0:
        report_content += f"- 이번 달 {ransomware_count}건의 랜섬웨어가 탐지되었습니다. 현재 보안 수준을 유지하세요.\n"
    else:
        report_content += "- 이번 달 랜섬웨어 탐지가 없었습니다. 우수한 보안 관리 상태입니다.\n"

    report_content += "\n---\n\n**보고서 종료**"

    # 파일 저장
    report_path = report_dir / f"monthly_report_{month_str}.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_content)

    return report_path

def generate_incident_report(incident):
    """사고 보고서 생성"""
    incident_id = incident['incident_id']
    file_name_safe = incident['file_name'].replace('/', '_').replace('\\', '_')
    report_dir = REPORTS_DIR / "incidents" / f"{incident_id}_{file_name_safe}"
    os.makedirs(report_dir, exist_ok=True)

    # 보고서 내용 생성
    report_content = f"""# 랜섬웨어 사고 대응 보고서
**사고 ID:** {incident_id}
**생성 시간:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 1. 사고 개요

- **파일명:** `{incident['file_name']}`
- **파일 경로:** `{incident['file_path']}`
- **탐지 시간:** {incident['created_at']}
- **랜섬웨어 확률:** {incident['probability']:.2%}
- **우선순위:** {incident['priority']}
- **담당자:** {incident['assigned_to']}
- **현재 상태:** {incident['status']}

---

## 2. 사고 타임라인

"""

    for event in incident['timeline']:
        timestamp = datetime.fromisoformat(event['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        report_content += f"### {timestamp} - {event['status']}\n{event['description']}\n\n"

    report_content += "---\n\n## 3. 대응 체크리스트\n\n"

    for task in incident['checklist']:
        status = "✅ 완료" if task['completed'] else "⬜ 미완료"
        report_content += f"- {status}: {task['task']}\n"

    report_content += "\n---\n\n## 4. 조치 사항\n\n"

    if incident['status'] == '완료':
        report_content += "모든 대응 절차가 완료되었습니다.\n"
    else:
        report_content += f"현재 '{incident['status']}' 상태로 대응이 진행중입니다.\n"

    report_content += "\n---\n\n**보고서 종료**"

    # 파일 저장
    report_path = report_dir / "incident_report.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_content)

    # JSON 상세 데이터 저장
    json_path = report_dir / "analysis_details.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(incident, f, ensure_ascii=False, indent=2)

    return report_path

# --- 13. 페이지 3: 보고서 작성 ---
def render_report_generation():
    """페이지 3: 보고서 작성"""
    st.header("📝 보고서 작성")
    st.markdown("---")

    st.subheader("📅 정기 보고서 생성")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("### 일간 보고서")
        date_input = st.date_input("날짜 선택", value=datetime.now().date())

        if st.button("일간 보고서 생성", key="daily_btn"):
            with st.spinner("일간 보고서 생성 중..."):
                report_path = generate_daily_report(date_input)
                if report_path:
                    st.success(f"✅ 보고서 생성 완료!")
                    st.code(str(report_path))

                    # 보고서 미리보기
                    with open(report_path, 'r', encoding='utf-8') as f:
                        st.markdown(f.read())
                else:
                    st.warning("해당 날짜에 데이터가 없습니다.")

    with col2:
        st.markdown("### 주간 보고서")
        week_input = st.text_input("주차 선택 (예: 2025-W47)", value=f"{datetime.now().year}-W{datetime.now().isocalendar()[1]:02d}")

        if st.button("주간 보고서 생성", key="weekly_btn"):
            with st.spinner("주간 보고서 생성 중..."):
                report_path = generate_weekly_report(week_input)
                if report_path:
                    st.success(f"✅ 보고서 생성 완료!")
                    st.code(str(report_path))

                    # 보고서 미리보기
                    with open(report_path, 'r', encoding='utf-8') as f:
                        st.markdown(f.read())
                else:
                    st.warning("해당 주차에 데이터가 없습니다.")

    with col3:
        st.markdown("### 월간 보고서")
        month_input = st.text_input("월 선택 (예: 2025-11)", value=f"{datetime.now().year}-{datetime.now().month:02d}")

        if st.button("월간 보고서 생성", key="monthly_btn"):
            with st.spinner("월간 보고서 생성 중..."):
                report_path = generate_monthly_report(month_input)
                if report_path:
                    st.success(f"✅ 보고서 생성 완료!")
                    st.code(str(report_path))

                    # 보고서 미리보기
                    with open(report_path, 'r', encoding='utf-8') as f:
                        st.markdown(f.read())
                else:
                    st.warning("해당 월에 데이터가 없습니다.")

    st.markdown("---")

    # 사고 보고서 생성
    st.subheader("🚨 사고 보고서 생성")

    incidents = load_incidents()
    if incidents:
        incident_options = {f"{inc['incident_id']} - {inc['file_name']}": inc for inc in incidents}
        selected_incident_key = st.selectbox("사고 선택", list(incident_options.keys()))

        if st.button("사고 보고서 생성", key="incident_btn"):
            selected_incident = incident_options[selected_incident_key]
            with st.spinner("사고 보고서 생성 중..."):
                report_path = generate_incident_report(selected_incident)
                st.success(f"✅ 사고 보고서 생성 완료!")
                st.code(str(report_path))

                # 보고서 미리보기
                with open(report_path, 'r', encoding='utf-8') as f:
                    st.markdown(f.read())
    else:
        st.info("생성할 사고가 없습니다.")

    st.markdown("---")

    # 보고서 디렉토리 트리 표시
    st.subheader("📂 보고서 디렉토리 구조")

    if st.button("디렉토리 새로고침"):
        st.rerun()

    # 디렉토리 트리 생성
    tree_structure = ""
    for root, dirs, files in os.walk(REPORTS_DIR):
        level = root.replace(str(REPORTS_DIR), '').count(os.sep)
        indent = ' ' * 2 * level
        tree_structure += f"{indent}{os.path.basename(root)}/\n"
        sub_indent = ' ' * 2 * (level + 1)
        for file in files:
            tree_structure += f"{sub_indent}{file}\n"

    st.code(tree_structure, language="")


# --- 12. 메인 애플리케이션 로직 ---
ransomware_model = load_ransomware_model()

if "page" not in st.session_state:
    st.session_state.page = "실시간 보안 관제"

with st.sidebar:
    st.title("🛡️ V4 통합 보안 대시보드")
    st.markdown("---")
    page_options = {
        "실시간 보안 관제": "📡",
        "사고 대응": "🚨",
        "보고서 작성": "📝"
    }

    choice = st.radio(
        "메뉴를 선택하세요",
        options=list(page_options.keys()),
        format_func=lambda x: f"{page_options[x]} {x}"
    )

    if choice != st.session_state.page:
        st.session_state.page = choice
        st.rerun()

    st.markdown("---")
    if ransomware_model:
        st.success("**랜섬웨어 분석 엔진:** ✅ 준비 완료")
    else:
        st.error("**랜섬웨어 분석 엔진:** ❌ 로드 실패")
    st.markdown("---")

# 페이지 렌더링
if st.session_state.page == "실시간 보안 관제":
    if ransomware_model:
        render_realtime_soc_dashboard()
    else:
        st.error("랜섬웨어 분석 엔진이 로드되지 않아 이 페이지를 표시할 수 없습니다.")
elif st.session_state.page == "사고 대응":
    render_incident_response()
elif st.session_state.page == "보고서 작성":
    render_report_generation()
