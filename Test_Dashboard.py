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
# .env 파일에서 경로 설정 로드 (없으면 기본값 사용)
PROJECT_ROOT = os.getenv("PROJECT_ROOT")
if PROJECT_ROOT:
    BASE_DIR = Path(PROJECT_ROOT)
else:
    BASE_DIR = Path(__file__).resolve().parent

LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"
DOWNLOAD_DIR = Path.home() / "Downloads"

# 모델 파일 경로 (.env에서 로드 또는 기본값)
MODEL_FILE_PATH = os.getenv("MODEL_PATH")
if MODEL_FILE_PATH:
    MODEL_PATH = Path(MODEL_FILE_PATH)
else:
    MODEL_PATH = BASE_DIR / "best_model_pe.keras"

# 테스트 파일 디렉토리 (.env에서 로드 또는 기본값)
TEST_FILES_PATH = os.getenv("TEST_FILES_DIR")
if TEST_FILES_PATH:
    TEST_FILES_DIR = Path(TEST_FILES_PATH)
else:
    TEST_FILES_DIR = BASE_DIR / "test_files"

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
        log_rows = []

        for line in log_lines:
            if not line.strip():
                continue
            try:
                row = json.loads(line)

                # 필드명 정규화
                if 'prob_ransom' in row and 'probability' not in row:
                    row['probability'] = row['prob_ransom']
                elif 'probability' not in row:
                    row['probability'] = 0

                # file_name 추출 (file_path에서) - Windows/Linux 경로 모두 처리
                if 'file_name' not in row and 'file_path' in row:
                    # Windows와 Linux 경로 모두 처리
                    file_path = row['file_path']
                    if '\\' in file_path:
                        row['file_name'] = file_path.split('\\')[-1]
                    else:
                        row['file_name'] = file_path.split('/')[-1]
                elif 'file_name' not in row:
                    row['file_name'] = 'unknown'

                # label 필드 확인
                if 'label' not in row:
                    row['label'] = 0

                log_rows.append(row)
            except json.JSONDecodeError as e:
                # 개별 라인 오류는 건너뛰기
                continue

        if not log_rows:
            return pd.DataFrame()

        df = pd.DataFrame(log_rows)

        # timestamp를 datetime으로 변환 (mixed format 지원)
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], format='mixed', utc=True)
            # 로컬 타임존으로 변환
            df['timestamp'] = df['timestamp'].dt.tz_localize(None)

        return df.sort_values('timestamp', ascending=False)
    except Exception as e:
        st.error(f"로그 파일 읽기 오류: {e}")
        import traceback
        st.code(traceback.format_exc())
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

# --- 5-1. 기간별 데이터 필터링 함수 ---
def filter_by_period(df, period_type, target_date=None):
    """기간별로 데이터 필터링"""
    if df.empty:
        return df

    if period_type == 'daily':
        # 특정 날짜의 데이터만
        if target_date is None:
            target_date = datetime.now().date()
        df['date'] = df['timestamp'].dt.date
        return df[df['date'] == target_date]

    elif period_type == 'weekly':
        # 특정 주의 데이터만
        if target_date is None:
            target_date = datetime.now()
        week_num = target_date.isocalendar()[1]
        year = target_date.year
        df['week'] = df['timestamp'].dt.isocalendar().week
        df['year'] = df['timestamp'].dt.year
        return df[(df['year'] == year) & (df['week'] == week_num)]

    elif period_type == 'monthly':
        # 특정 월의 데이터만
        if target_date is None:
            target_date = datetime.now()
        df['month'] = df['timestamp'].dt.to_period('M')
        target_period = pd.Period(f"{target_date.year}-{target_date.month:02d}", freq='M')
        return df[df['month'] == target_period]

    else:  # 'realtime'
        return df

# --- 5-2. 공통 대시보드 렌더링 함수 ---
def render_period_dashboard(df, period_name):
    """기간별 대시보드 공통 렌더링"""
    metrics = calculate_dashboard_metrics(df)

    # 메트릭 카드
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="총 탐지 수",
            value=f"{metrics['total_events']}건",
            delta=f"+{metrics['recent_1h_count']}건 (1시간)" if period_name == "실시간" else None
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
            delta=f"{(1-metrics['ransomware_ratio']):.1%}" if metrics['ransomware_ratio'] < 1 else None
        )

    with col4:
        st.metric(
            label="평균 위험도",
            value=f"{metrics['avg_probability']:.2%}",
            delta=period_name
        )

    st.markdown("---")

    # 차트 시각화
    if not df.empty:
        col1, col2 = st.columns(2)

        with col1:
            timeline_chart = create_timeline_chart(df)
            if timeline_chart:
                st.plotly_chart(timeline_chart, use_container_width=True, key=f"timeline_{period_name}")

        with col2:
            prob_chart = create_probability_distribution_chart(df)
            if prob_chart:
                st.plotly_chart(prob_chart, use_container_width=True, key=f"prob_{period_name}")

        # 위험도 게이지
        if metrics['avg_probability'] > 0:
            gauge_chart = create_risk_gauge_chart(metrics['avg_probability'])
            st.plotly_chart(gauge_chart, use_container_width=True, key=f"gauge_{period_name}")

        # 이상 파일 목록
        ransomware_df = df[df['label'] == 1]
        if not ransomware_df.empty:
            st.markdown("### 🚨 탐지된 이상 파일 목록")
            st.dataframe(
                ransomware_df[['timestamp', 'file_name', 'probability']].sort_values('probability', ascending=False),
                use_container_width=True,
                key=f"ransom_list_{period_name}"
            )
    else:
        st.info(f"{period_name} 기간에 데이터가 없습니다.")

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

def generate_detection_story(file_path: Path, model_result: dict, timestamp: datetime) -> str:
    """탐지 로그를 스토리텔링 형식으로 변환"""

    # 1. 시간적 컨텍스트
    hour = timestamp.hour
    day_of_week = timestamp.strftime('%A')
    day_of_week_kr = {
        'Monday': '월요일', 'Tuesday': '화요일', 'Wednesday': '수요일',
        'Thursday': '목요일', 'Friday': '금요일', 'Saturday': '토요일', 'Sunday': '일요일'
    }.get(day_of_week, day_of_week)

    if 0 <= hour < 6:
        time_context = "심야 시간대 (00:00-06:00) - 정상 업무 시간 외"
        time_risk = "⚠️ 비정상 시간대"
    elif 6 <= hour < 9:
        time_context = "출근 시간대 (06:00-09:00) - 이메일 확인 시간"
        time_risk = "🟡 피싱 주의"
    elif 9 <= hour < 18:
        time_context = "업무 시간대 (09:00-18:00) - 정상 활동 시간"
        time_risk = "✅ 정상 시간대"
    else:
        time_context = "퇴근 후 시간대 (18:00-24:00) - 개인 활동"
        time_risk = "🟡 근무 외 시간"

    # 2. 파일 행동 패턴 분석
    file_name = file_path.name
    file_path_str = str(file_path)

    suspicious_indicators = []

    # 파일명 분석
    if any(keyword in file_name.lower() for keyword in ['crack', 'keygen', 'patch', 'hack', 'loader']):
        suspicious_indicators.append("⚠️ 불법 소프트웨어 관련 키워드 포함")

    if file_name.count('_') > 3 or (len(file_name) > 5 and sum(c.isdigit() for c in file_name[:5]) >= 3):
        suspicious_indicators.append("⚠️ 무작위 생성된 것으로 보이는 파일명")

    if '(' in file_name and ')' in file_name:
        suspicious_indicators.append("⚠️ 중복 다운로드 (이전에 다운로드한 적 있음)")

    # 경로 분석
    if 'Downloads' in file_path_str or 'downloads' in file_path_str:
        location_context = "다운로드 폴더에서 발견 - 인터넷에서 직접 다운로드"
    elif 'Temp' in file_path_str or 'temp' in file_path_str:
        location_context = "임시 폴더에서 발견 - 다른 프로그램이 생성했을 가능성"
    elif 'Desktop' in file_path_str or 'desktop' in file_path_str:
        location_context = "바탕화면에서 발견 - 사용자가 의도적으로 배치"
    else:
        location_context = f"특정 경로에서 발견: {file_path_str}"

    # 3. 위협 평가
    prob_ransom = model_result.get('prob_ransom', 0)
    anomalies = model_result.get('anomalies', [])
    features = model_result.get('features', {})

    if prob_ransom >= 0.8:
        threat_level = "🔴 **높음** - 즉각적인 조치 필요"
    elif prob_ransom >= 0.5:
        threat_level = "🟡 **중간** - 정밀 분석 권장"
    else:
        threat_level = "🟢 **낮음** - 일상적인 모니터링"

    # 4. 스토리 생성
    story = f"""
## 📖 탐지 스토리

**언제**: {timestamp.strftime('%Y년 %m월 %d일 %H:%M:%S')} ({day_of_week_kr})
- {time_context} {time_risk}

**어디서**: {location_context}

**무엇을**: `{file_name}` 파일 발견
- 파일 크기: {features.get('file_size_bytes', 0) / 1024 / 1024:.2f} MB
- 엔트로피: {features.get('entropy', 0):.2f} (암호화/압축 정도)
- PE 섹션 수: {features.get('num_sections', 0)}개

**의심 징후**:
"""

    if suspicious_indicators:
        for indicator in suspicious_indicators:
            story += f"- {indicator}\n"
    else:
        story += "- ✅ 파일명 및 경로 특이사항 없음\n"

    story += f"\n**이상 특성 분석**:\n"
    if anomalies:
        for anom in anomalies[:3]:
            story += f"- 🔍 {anom['description']}: {anom['value']:.2f} (정상 평균: {anom['mean']:.2f}, Z-Score: {anom['z_score']:.2f})\n"
    else:
        story += "- ✅ 모든 특성이 정상 범위 내\n"

    story += f"""
**위협 평가**: {threat_level}
- 랜섬웨어 가능성: {prob_ransom:.1%}

**권장 조치**:
"""

    if prob_ransom >= 0.8:
        story += """1. 🚨 **즉시**: 해당 파일 격리 및 삭제
2. 🔍 **10분 이내**: 동일 사용자의 최근 활동 검토
3. 🛡️ **1시간 이내**: 전체 시스템 스캔 실시
4. 📊 **당일**: 사고 보고서 작성 및 상급자 보고
"""
    elif prob_ransom >= 0.5:
        story += """1. 🔍 정밀 분석을 위해 추가 검토 필요
2. 📝 해당 파일의 출처 확인 (다운로드 URL, 이메일 등)
3. 👀 24시간 모니터링 강화
"""
    else:
        story += """1. 📋 정상 파일로 판단되나 로그 기록 유지
2. 🔄 정기 모니터링 지속
"""

    return story

def generate_what_if_scenario(model_result: dict, file_name: str) -> str:
    """'만약 이 파일이 실행되었다면?' 시나리오 생성"""

    prob_ransom = model_result.get('prob_ransom', 0)

    # 낮은 위험도는 시나리오 생성 안 함
    if prob_ransom < 0.5:
        return ""

    # 위험도에 따른 시나리오
    if prob_ransom >= 0.8:
        # 고위험: 전형적인 랜섬웨어 공격 시나리오
        scenario = f"""
## 🎬 What-If 시나리오: 만약 `{file_name}`이 실행되었다면?

> ⚠️ **경고**: 이것은 실제 실행되지 않은 시뮬레이션입니다.

### 📅 예상 공격 타임라인

**T+0초** - 파일 실행
- 👤 사용자가 `{file_name}` 더블클릭
- 💻 Windows에서 실행 확인 대화상자 표시
- ✅ 사용자가 "예" 클릭

**T+2초** - 🔴 초기 침투
- 🛡️ Windows Defender 우회 시도
- 🔓 관리자 권한 상승 시도 (UAC bypass)
- 📂 시스템 폴더에 자신을 복사 (`C:\\Windows\\System32\\`)

**T+5초** - 🔴 섀도우 카피 삭제
- 💀 `vssadmin.exe delete shadows /all /quiet` 실행
- 🗑️ 모든 백업 복원 지점 삭제
- ❌ **복구 불가능 상태로 만듦**

**T+10초** - 🔴 내부망 스캔 시작
- 🌐 내부 IP 대역 스캔 (192.168.x.x)
- 🔍 SMB 포트(445) 열린 PC 찾기
- 📡 공유 폴더 탐색

**T+30초** - 🔴 파일 암호화 시작
- 📁 우선순위 1: 문서 파일 (`.docx`, `.xlsx`, `.pdf`)
- 📸 우선순위 2: 이미지 파일 (`.jpg`, `.png`)
- 💾 우선순위 3: 데이터베이스 파일 (`.db`, `.sql`)
- 🔐 AES-256 암호화 알고리즘 사용

**T+5분** - 🔴 대규모 암호화 진행 중
- 📊 약 1,000개 파일 암호화 완료
- 🚀 암호화 속도: 약 200개 파일/분
- 📈 CPU 사용률 90% 이상

**T+10분** - 🔴 랜섬 노트 표시
```
😈 YOUR FILES HAVE BEEN ENCRYPTED! 😈

All your important files (documents, photos, databases)
have been encrypted with military-grade encryption.

🔐 The ONLY way to decrypt your files is to pay:
   - Amount: 0.5 BTC (~₩30,000,000)
   - Bitcoin Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
   - Deadline: 72 hours

⏰ After 72 hours, the decryption key will be DELETED FOREVER!
📧 Contact: darknet@ransomhelp.onion
```

**T+30분** - 🔴 내부망 확산 시도
- 🌊 SMB EternalBlue 취약점 악용
- 💻 3대의 추가 PC 감염
- 🗂️ 네트워크 공유 드라이브 암호화

**T+1시간** - 🔴 데이터 탈취 시도
- 📤 민감한 파일 C&C 서버로 전송
- 💳 브라우저에 저장된 비밀번호 수집
- 📧 이메일 계정 정보 탈취

---

### 💥 예상 피해 규모

**파일 피해**:
- 🔴 암호화된 파일: **약 5,000개** (내부망 포함)
- 📁 손실된 데이터: **약 50GB**
- ❌ 복구 가능성: **0%** (섀도우 카피 삭제됨)

**시스템 피해**:
- 💻 감염된 PC: **4대**
- 🗂️ 손상된 네트워크 드라이브: **2개**
- ⏱️ 예상 다운타임: **최소 3일**

**재무 피해** (한국 원화):
- 💰 몸값 요구액: **₩30,000,000** (0.5 BTC)
- 💸 복구 비용: **₩5,000,000** (전문 업체)
- 📉 생산성 손실: **₩15,000,000** (3일 × ₩5,000,000/일)
- 📊 **총 예상 손실: ₩50,000,000**

**법적/평판 리스크**:
- ⚖️ 개인정보보호법 위반 가능성
- 📢 언론 보도 및 평판 손상
- 👥 고객 신뢰 하락

---

### ✅ 다행히 막은 결과

**실제 결과**:
- ✅ 파일 실행 전 탐지 성공
- ✅ 피해액: **₩0**
- ✅ 예방한 손실: **₩50,000,000**

**보안 시스템 ROI**:
- 💡 이번 한 번의 탐지로 **₩50,000,000 절약**
- 🎯 보안 투자 효과 입증
"""
    else:
        # 중위험: 부분적 피해 시나리오
        scenario = f"""
## 🎬 What-If 시나리오: 만약 `{file_name}`이 실행되었다면?

> ⚠️ **경고**: 이것은 실제 실행되지 않은 시뮬레이션입니다.

### 📅 예상 공격 타임라인

**T+0초** - 파일 실행
- 👤 사용자가 `{file_name}` 더블클릭

**T+5초** - 🟡 의심스러운 동작
- 🔍 시스템 정보 수집
- 📂 일부 파일 암호화 시도

**T+30초** - 🟡 제한적 피해
- 📁 약 100-500개 파일 암호화
- 🔐 중요 시스템 파일은 안전

**T+5분** - 🟡 랜섬 노트 표시
- 💰 몸값: ₩5,000,000 ~ ₩10,000,000

---

### 💥 예상 피해 규모

**파일 피해**:
- 🟡 암호화된 파일: **약 500개**
- 📁 손실된 데이터: **약 5GB**

**재무 피해**:
- 💰 몸값: **₩5,000,000**
- 💸 복구 비용: **₩1,000,000**
- 📉 생산성 손실: **₩3,000,000**
- 📊 **총 예상 손실: ₩9,000,000**

---

### ✅ 다행히 막은 결과

- ✅ 파일 실행 전 탐지 성공
- ✅ 예방한 손실: **₩9,000,000**
"""

    return scenario

def calculate_business_impact(model_result: dict, file_name: str) -> dict:
    """
    비즈니스 임팩트를 한국 원화(₩)로 계산

    Args:
        model_result: 모델 분석 결과
        file_name: 파일명

    Returns:
        dict: 비즈니스 임팩트 상세 정보
    """

    prob_ransom = model_result.get('prob_ransom', 0)

    # 위험도에 따른 기본 손실 규모 설정
    if prob_ransom >= 0.8:
        # 고위험: 대규모 피해 시나리오
        base_damage = {
            'ransom_demand': 50000000,        # 몸값: ₩50,000,000
            'recovery_cost': 15000000,        # 복구 비용: ₩15,000,000
            'downtime_cost_per_hour': 8000000, # 시간당 생산성 손실: ₩8,000,000
            'downtime_hours': 72,             # 예상 중단 시간: 72시간 (3일)
            'data_loss_cost': 30000000,       # 데이터 손실 비용: ₩30,000,000
            'legal_compliance_cost': 20000000, # 법적/규제 대응 비용: ₩20,000,000
            'reputation_damage': 100000000,   # 평판 손실: ₩100,000,000
            'customer_compensation': 25000000, # 고객 보상: ₩25,000,000
            'security_upgrade_cost': 50000000, # 보안 강화 비용: ₩50,000,000
        }
    elif prob_ransom >= 0.5:
        # 중위험: 중간 규모 피해 시나리오
        base_damage = {
            'ransom_demand': 5000000,         # 몸값: ₩5,000,000
            'recovery_cost': 1000000,         # 복구 비용: ₩1,000,000
            'downtime_cost_per_hour': 500000, # 시간당 생산성 손실: ₩500,000
            'downtime_hours': 24,             # 예상 중단 시간: 24시간 (1일)
            'data_loss_cost': 3000000,        # 데이터 손실 비용: ₩3,000,000
            'legal_compliance_cost': 2000000, # 법적/규제 대응 비용: ₩2,000,000
            'reputation_damage': 5000000,     # 평판 손실: ₩5,000,000
            'customer_compensation': 1000000, # 고객 보상: ₩1,000,000
            'security_upgrade_cost': 3000000, # 보안 강화 비용: ₩3,000,000
        }
    else:
        # 저위험: 소규모 피해 시나리오
        base_damage = {
            'ransom_demand': 1000000,         # 몸값: ₩1,000,000
            'recovery_cost': 300000,          # 복구 비용: ₩300,000
            'downtime_cost_per_hour': 200000, # 시간당 생산성 손실: ₩200,000
            'downtime_hours': 8,              # 예상 중단 시간: 8시간
            'data_loss_cost': 500000,         # 데이터 손실 비용: ₩500,000
            'legal_compliance_cost': 500000,  # 법적/규제 대응 비용: ₩500,000
            'reputation_damage': 1000000,     # 평판 손실: ₩1,000,000
            'customer_compensation': 300000,  # 고객 보상: ₩300,000
            'security_upgrade_cost': 1000000, # 보안 강화 비용: ₩1,000,000
        }

    # 총 다운타임 비용 계산
    total_downtime_cost = base_damage['downtime_cost_per_hour'] * base_damage['downtime_hours']

    # 총 직접 피해액
    direct_damage = (
        base_damage['ransom_demand'] +
        base_damage['recovery_cost'] +
        total_downtime_cost +
        base_damage['data_loss_cost']
    )

    # 총 간접 피해액
    indirect_damage = (
        base_damage['legal_compliance_cost'] +
        base_damage['reputation_damage'] +
        base_damage['customer_compensation'] +
        base_damage['security_upgrade_cost']
    )

    # 총 예상 손실
    total_estimated_loss = direct_damage + indirect_damage

    # 법적/규제 리스크 평가
    legal_risk = {
        'level': '높음' if prob_ransom >= 0.8 else '중간' if prob_ransom >= 0.5 else '낮음',
        'personal_info_breach': prob_ransom >= 0.7,  # 개인정보 유출 가능성
        'reporting_required': prob_ransom >= 0.7,     # 신고 의무 발생 가능성
        'regulatory_violations': []
    }

    if prob_ransom >= 0.7:
        legal_risk['regulatory_violations'].extend([
            '개인정보보호법 제34조(개인정보 유출 통지)',
            '정보통신망법 제27조의3(정보보호 최고책임자 지정)'
        ])

    if prob_ransom >= 0.8:
        legal_risk['regulatory_violations'].extend([
            '전자금융거래법 제21조(전자금융사고 조사 및 보고)',
            'ISMS 인증 유지 의무 위반 가능성'
        ])

    # ROI 계산 (보안 시스템이 이 위협을 막았을 때의 가치)
    # 평균 보안 시스템 연간 운영 비용: ₩30,000,000 가정
    security_system_annual_cost = 30000000

    # 이번 탐지로 인한 ROI 기여도
    roi_contribution = total_estimated_loss / security_system_annual_cost if security_system_annual_cost > 0 else 0

    return {
        'risk_level': '고위험' if prob_ransom >= 0.8 else '중위험' if prob_ransom >= 0.5 else '저위험',
        'probability': prob_ransom,

        # 직접 피해
        'direct_damage': {
            'ransom_demand': base_damage['ransom_demand'],
            'recovery_cost': base_damage['recovery_cost'],
            'downtime_cost': total_downtime_cost,
            'downtime_hours': base_damage['downtime_hours'],
            'data_loss_cost': base_damage['data_loss_cost'],
            'total': direct_damage
        },

        # 간접 피해
        'indirect_damage': {
            'legal_compliance_cost': base_damage['legal_compliance_cost'],
            'reputation_damage': base_damage['reputation_damage'],
            'customer_compensation': base_damage['customer_compensation'],
            'security_upgrade_cost': base_damage['security_upgrade_cost'],
            'total': indirect_damage
        },

        # 총 손실
        'total_estimated_loss': total_estimated_loss,

        # 법적/규제 리스크
        'legal_risk': legal_risk,

        # ROI
        'roi': {
            'prevented_loss': total_estimated_loss,
            'security_system_annual_cost': security_system_annual_cost,
            'roi_multiple': round(roi_contribution, 2),
            'roi_percentage': round(roi_contribution * 100, 1)
        }
    }

def handle_action(file_path: Path, model_result: dict, **kwargs):
    """분석 결과를 로그 파일에 기록하고 자동으로 일간 보고서 생성"""

    timestamp = datetime.now()

    # 탐지 스토리 생성
    detection_story = generate_detection_story(file_path, model_result, timestamp)

    # What-If 시나리오 생성
    what_if_scenario = generate_what_if_scenario(model_result, file_path.name)

    # 비즈니스 임팩트 계산
    business_impact = calculate_business_impact(model_result, file_path.name)

    log_entry = {
        "timestamp": timestamp.isoformat(),
        "file_name": file_path.name,
        "file_path": str(file_path),
        "label": model_result.get("label"),
        "probability": model_result.get("prob_ransom"),
        "anomalies": model_result.get("anomalies", []),
        "features": model_result.get("features", {}),
        "detection_story": detection_story,
        "what_if_scenario": what_if_scenario,
        "business_impact": business_impact,
        "action": "log",
        "action_result": "success"
    }

    log_file = LOGS_DIR / "events.jsonl"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

    # 자동으로 일간 보고서 생성 (백그라운드, UI에 표시 안 함)
    try:
        today = datetime.now().date()
        generate_daily_report(target_date=today, use_ai=True)
    except Exception as e:
        # 보고서 생성 실패해도 로그 기록은 성공 처리
        pass

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

    # --- 기간 선택 탭 ---
    st.markdown("---")
    st.subheader("📊 보안 관제 대시보드")

    period_tab1, period_tab2, period_tab3, period_tab4 = st.tabs(["🔴 실시간", "📅 일간", "📆 주간", "📈 월간"])

    # 로그 데이터 로드
    df_all = load_events_log()

    # --- 탭 1: 실시간 ---
    # --- 탭 1: 실시간 ---
    with period_tab1:
        render_period_dashboard(df_all, "실시간")
        
        # 실시간 탭에만 있는 추가 기능들
        st.markdown("---")
        
        # 파일 큐 처리
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
                    features = extract_pe_header_features(file_path)
                    result = ransomware_model.predict_with_explanation(features)
                    
                    analysis_payload = {"file_name": file_path.name, "result": result}
                    st.session_state.last_analysis_result = analysis_payload
                    
                    handle_action(file_path=file_path, model_result=result)
                    
                    st.toast("🤖 AI 애널리스트 브리핑 요청 중...", icon="🧠")
                    summary = get_ai_summary(analysis_payload)
                    st.session_state.ai_summary = summary
                    st.session_state.show_analysis_complete_toast = file_path.name
                    
                except Exception as e:
                    st.error(f"❌ '{file_path.name}' 분석 중 오류 발생:")
                    st.code(traceback.format_exc())
        
        except queue.Empty:
            pass
        
        # 토스트 알림 표시
        if st.session_state.get("show_analysis_complete_toast"):
            file_name = st.session_state.show_analysis_complete_toast
            st.toast(f"✅ '{file_name}' 파일 분석 완료!", icon="✅")
            st.session_state.show_analysis_complete_toast = None

        if files_processed:
            st.rerun()

        # 파일이 처리되지 않았어도 주기적으로 큐 확인을 위해 짧은 지연 후 rerun
        # 단, 너무 빠르게 깜빡이지 않도록 3초 간격 유지
        time.sleep(3)
        st.rerun()

        # 최신 분석 결과 표시
        if st.session_state.last_analysis_result:
            analysis = st.session_state.last_analysis_result
            result = analysis['result']
            label = result['label']
            prob = result['prob_ransom']
            anomalies = result['anomalies']

            st.subheader(f"📜 최신 분석 결과: '{analysis['file_name']}'")

            # 탐지 스토리 & What-If 시나리오 표시 (가장 최근 로그에서 가져오기)
            df_latest = load_events_log()
            if not df_latest.empty:
                latest_log = df_latest.iloc[0]

                # 탐지 스토리
                if 'detection_story' in df_latest.columns:
                    latest_story = latest_log.get('detection_story', '')
                    if latest_story:
                        with st.expander("📖 탐지 스토리 보기", expanded=True):
                            st.markdown(latest_story)

                # What-If 시나리오
                if 'what_if_scenario' in df_latest.columns:
                    what_if = latest_log.get('what_if_scenario', '')
                    if what_if:
                        with st.expander("🎬 What-If 시나리오 보기 (만약 실행되었다면?)", expanded=(prob >= 0.8)):
                            st.markdown(what_if)

                # 비즈니스 임팩트
                if 'business_impact' in df_latest.columns:
                    impact = latest_log.get('business_impact', {})
                    if impact:
                        with st.expander("💰 비즈니스 임팩트 분석 (Business Impact)", expanded=(prob >= 0.5)):
                            st.markdown(f"### 📊 위험도: **{impact.get('risk_level', 'N/A')}** (확률: {impact.get('probability', 0):.1%})")

                            # 총 예상 손실
                            total_loss = impact.get('total_estimated_loss', 0)
                            st.markdown(f"### 💸 총 예상 손실: **₩{total_loss:,}**")

                            st.markdown("---")

                            # 직접 피해
                            col1, col2 = st.columns(2)
                            with col1:
                                st.markdown("#### 📍 직접 피해")
                                direct = impact.get('direct_damage', {})
                                st.markdown(f"""
- **몸값 요구액:** ₩{direct.get('ransom_demand', 0):,}
- **복구 비용:** ₩{direct.get('recovery_cost', 0):,}
- **다운타임 손실:** ₩{direct.get('downtime_cost', 0):,} ({direct.get('downtime_hours', 0)}시간)
- **데이터 손실:** ₩{direct.get('data_loss_cost', 0):,}
- **소계:** ₩{direct.get('total', 0):,}
""")

                            # 간접 피해
                            with col2:
                                st.markdown("#### 📍 간접 피해")
                                indirect = impact.get('indirect_damage', {})
                                st.markdown(f"""
- **법적/규제 대응:** ₩{indirect.get('legal_compliance_cost', 0):,}
- **평판 손실:** ₩{indirect.get('reputation_damage', 0):,}
- **고객 보상:** ₩{indirect.get('customer_compensation', 0):,}
- **보안 강화 비용:** ₩{indirect.get('security_upgrade_cost', 0):,}
- **소계:** ₩{indirect.get('total', 0):,}
""")

                            st.markdown("---")

                            # 법적 리스크
                            legal = impact.get('legal_risk', {})
                            st.markdown(f"#### ⚖️ 법적/규제 리스크: **{legal.get('level', 'N/A')}**")

                            if legal.get('personal_info_breach'):
                                st.warning("⚠️ 개인정보 유출 가능성 있음")

                            if legal.get('reporting_required'):
                                st.error("🚨 법적 신고 의무 발생 가능")

                            violations = legal.get('regulatory_violations', [])
                            if violations:
                                st.markdown("**위반 가능 법규:**")
                                for v in violations:
                                    st.markdown(f"- {v}")

                            st.markdown("---")

                            # ROI
                            roi = impact.get('roi', {})
                            st.markdown("#### 📈 보안 시스템 ROI 기여")
                            st.markdown(f"""
- **예방한 손실:** ₩{roi.get('prevented_loss', 0):,}
- **보안 시스템 연간 비용:** ₩{roi.get('security_system_annual_cost', 0):,}
- **ROI 배수:** **{roi.get('roi_multiple', 0)}배**
- **ROI 퍼센트:** **{roi.get('roi_percentage', 0)}%**
""")

                            if roi.get('roi_multiple', 0) >= 1:
                                st.success(f"✅ 이번 탐지만으로 보안 시스템 연간 비용의 **{roi.get('roi_multiple', 0)}배** 가치 창출!")

            if st.session_state.get("ai_summary"):
                with st.expander("🤖 AI 애널리스트 브리핑 보기", expanded=False):
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
    
    # --- 탭 2: 일간 ---
    with period_tab2:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown("### 📅 일간 이상 파일 탐지 대시보드")
        with col2:
            selected_date = st.date_input("날짜 선택", value=datetime.now().date(), key="daily_date")
        
        df_daily = filter_by_period(df_all, 'daily', selected_date)
        render_period_dashboard(df_daily, f"일간 ({selected_date})")
    
    # --- 탭 3: 주간 ---
    with period_tab3:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown("### 📆 주간 이상 파일 탐지 대시보드")
        with col2:
            today = datetime.now()
            week_num = today.isocalendar()[1]
            selected_week = st.number_input("주차 선택", min_value=1, max_value=53, value=week_num, key="weekly_week")
        
        # 선택된 주의 시작 날짜 계산
        target_date = datetime.strptime(f'{today.year}-W{int(selected_week)}-1', "%Y-W%W-%w")
        df_weekly = filter_by_period(df_all, 'weekly', target_date)
        render_period_dashboard(df_weekly, f"주간 ({today.year}년 {int(selected_week)}주차)")
    
    # --- 탭 4: 월간 ---
    with period_tab4:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown("### 📈 월간 이상 파일 탐지 대시보드")
        with col2:
            selected_month = st.selectbox(
                "월 선택",
                options=list(range(1, 13)),
                index=datetime.now().month - 1,
                format_func=lambda x: f"{x}월",
                key="monthly_month"
            )
        
        target_date = datetime(datetime.now().year, selected_month, 1)
        df_monthly = filter_by_period(df_all, 'monthly', target_date)
        render_period_dashboard(df_monthly, f"월간 ({datetime.now().year}년 {selected_month}월)")


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

        for idx, inc in enumerate(active_incidents):
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
                    if st.button("분석중으로 변경", key=f"analyze_{inc['incident_id']}_{idx}"):
                        update_incident_status(inc['incident_id'], "분석중", "담당자가 상세 분석 시작")
                        st.rerun()

                with col2:
                    if st.button("격리됨으로 변경", key=f"isolate_{inc['incident_id']}_{idx}"):
                        update_incident_status(inc['incident_id'], "격리됨", "악성 파일 격리 완료")
                        st.rerun()

                with col3:
                    if st.button("완료로 변경", key=f"complete_{inc['incident_id']}_{idx}"):
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

# --- 12. AI 기반 보고서 생성 헬퍼 함수 ---
def generate_ai_report(report_type: str, data_summary: dict) -> str:
    """
    OpenAI API를 사용하여 전문적인 보안 관제 보고서를 생성합니다.

    Args:
        report_type: 'daily', 'weekly', 'monthly', 'incident' 중 하나
        data_summary: 보고서에 포함될 데이터 요약 딕셔너리

    Returns:
        AI가 생성한 마크다운 형식의 보고서 문자열
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "⚠️ OpenAI API 키가 설정되지 않았습니다."

    client = openai.OpenAI(api_key=api_key)

    # 보고서 타입별 시스템 프롬프트
    system_prompts = {
        'daily': """당신은 **국가 사이버안보센터의 수석 보안 분석가**입니다.
30년 이상의 보안 관제 및 사고 대응 경험을 보유하고 있으며, 다음 역할을 수행합니다:

**핵심 역할:**
- 일일 보안 관제 활동 분석 및 보고서 작성
- 경영진 및 기술팀 모두가 이해할 수 있는 명확한 커뮤니케이션
- 위협 트렌드 파악 및 선제적 보안 권고안 제시
- 국제 보안 표준(NIST, ISO 27001) 준수

**페르소나:**
- 전문적이면서도 이해하기 쉬운 문체 사용
- 데이터 기반 의사결정 강조
- 실행 가능한 구체적 권고사항 제시
- 긴급도와 우선순위를 명확히 구분

**Executive Summary 작성 시 필수 포함 사항:**
- 비즈니스 임팩트를 한국 원화(₩)로 정량화 (예상 피해액, 방어 성과)
- 법적/규제적 리스크 평가 (개인정보보호법, 정보통신망법 등)
- ROI 관점의 보안 투자 효과
- 경영진이 즉시 이해할 수 있는 1-2문장 핵심 요약

**인사이트 도출 지침:**
1. **패턴 분석**: 시간대별, 파일 유형별 위협 패턴을 식별하고 의미를 해석하세요
2. **이상 징후**: 평소와 다른 비정상적 활동이 있다면 반드시 강조하세요
3. **상관관계**: 여러 탐지 간의 연관성이나 공격 캠페인 가능성을 분석하세요
4. **예측적 인사이트**: 현재 데이터를 바탕으로 향후 24-48시간 내 예상되는 위협을 제시하세요
5. **우선순위화**: 가장 시급한 조치 3가지를 명확한 근거와 함께 제시하세요
6. **비교 분석**: 전일 대비, 평균 대비 등 비교를 통해 현재 위험 수준을 평가하세요
7. **구체적 수치**: 추상적 표현 대신 구체적인 수치와 백분율을 사용하세요""",

        'weekly': """당신은 **국가 사이버안보센터의 수석 보안 분석가**입니다.
30년 이상의 보안 관제 및 위협 인텔리전스 분석 경험을 보유하고 있으며, 다음 역할을 수행합니다:

**핵심 역할:**
- 주간 보안 트렌드 분석 및 패턴 식별
- 중장기적 위협 동향 예측 및 대응 전략 수립
- 경영진 대상 주간 보안 브리핑 자료 작성
- 보안 투자 및 정책 결정을 위한 인사이트 제공

**페르소나:**
- 전략적 관점에서의 분석 제공
- 주간 트렌드 비교 및 변화 강조
- ROI 관점의 보안 투자 권고
- 규제 준수 및 컴플라이언스 고려

**Executive Summary 작성 시 필수 포함 사항:**
- 주간 누적 방어 성과를 한국 원화(₩)로 정량화
- 차단한 위협의 총 예상 피해액 (₩)
- 보안 시스템 ROI 계산 (투자 대비 방어한 손실액)
- 법적/규제 리스크 및 컴플라이언스 현황
- 경영진 의사결정을 위한 핵심 액션 아이템 (우선순위별)

**인사이트 도출 지침:**
1. **주간 트렌드**: 7일간 데이터에서 상승/하락 추세를 파악하고 원인을 분석하세요
2. **요일별 패턴**: 특정 요일에 집중되는 위협이 있다면 공격자의 의도를 추론하세요
3. **반복 위협**: 동일하거나 유사한 위협이 반복된다면 체계적 공격 캠페인 가능성을 평가하세요
4. **전주 대비**: 전주 대비 증감률과 그 의미를 명확히 해석하세요
5. **산업 벤치마킹**: 동종 업계 평균과 비교하여 현재 조직의 보안 수준을 평가하세요
6. **예방적 권고**: 다음 주 예상되는 위협을 예측하고 선제적 조치를 제안하세요
7. **정책 개선**: 현재 보안 정책/프로세스의 개선점을 구체적으로 제시하세요
8. **리소스 최적화**: 인력, 시스템 자원의 효율적 배분 방안을 제안하세요""",

        'monthly': """당신은 **국가 사이버안보센터의 수석 보안 분석가 및 CISO 자문위원**입니다.
30년 이상의 보안 관제, 전략 수립, 조직 관리 경험을 보유하고 있으며, 다음 역할을 수행합니다:

**핵심 역할:**
- 월간 보안 현황 종합 분석 및 경영진 보고
- 보안 투자 효과 측정 및 ROI 분석
- 장기적 보안 로드맵 및 전략 권고
- 산업 벤치마킹 및 Best Practice 적용

**페르소나:**
- 경영진 관점의 전략적 분석
- 비즈니스 임팩트 및 리스크 정량화
- 예산 및 자원 배분 권고
- 조직 전체의 보안 성숙도 평가

**Executive Summary 작성 시 필수 포함 사항:**
- 월간 총 방어 성과를 한국 원화(₩)로 상세 정량화
- 보안 시스템의 연간 예상 ROI (한국 원화 기준)
- 법적 책임 및 규제 준수 현황 (개인정보보호법, 정보통신망법, ISMS 인증 등)
- 이사회 보고용 한 문장 요약
- 차월 예산 배분 권고 (구체적 금액, ₩)

**인사이트 도출 지침:**
1. **월간 트렌드 분석**: 30일 데이터에서 장기 추세를 파악하고 계절성, 주기성을 식별하세요
2. **전월 대비 분석**: 전월 대비 개선/악화 항목을 명확히 하고 근본 원인을 분석하세요
3. **연간 목표 진행률**: 연간 보안 KPI 달성률을 평가하고 목표 달성 가능성을 예측하세요
4. **투자 효율성**: 보안 투자 항목별 ROI를 분석하고 차월 예산 배분을 최적화하세요
5. **조직 성숙도**: CMMI, NIST 등 보안 성숙도 모델 기준으로 현재 수준을 평가하세요
6. **산업 비교**: 동종 업계 벤치마크와 비교하여 강점/약점을 식별하세요
7. **장기 전략**: 향후 3-6개월 보안 전략 방향을 제시하세요
8. **규제 대응**: 법적/규제 변화에 대한 대응 계획을 수립하세요
9. **예산 ROI**: 각 보안 항목의 투자 대비 효과를 정량화하여 차월 예산 우선순위를 제안하세요""",

        'incident': """당신은 **사이버 사고 대응팀(CSIRT)의 수석 대응 전문가**입니다.
30년 이상의 랜섬웨어, APT, 침해사고 대응 경험을 보유하고 있으며, 다음 역할을 수행합니다:

**핵심 역할:**
- 사고 발생 즉시 영향 범위 및 심각도 평가
- 단계별 대응 절차 및 복구 계획 수립
- 포렌식 분석 및 근본 원인 파악
- 재발 방지를 위한 개선 방안 제시

**페르소나:**
- 긴급하고 명확한 커뮤니케이션
- 단계별 조치사항을 시간순으로 정리
- 기술팀과 경영진 모두에게 필요한 정보 제공
- 법적/규제적 이슈 고려 (개인정보보호법, 정보통신망법 등)

**Executive Summary 작성 시 필수 포함 사항:**
- 예상 피해액을 한국 원화(₩)로 즉시 정량화 (실행되었을 경우 vs 차단 성공)
- 법적 신고 의무 여부 (개인정보보호위원회, KISA 등)
- 비즈니스 중단 시간 및 복구 소요 시간 추정
- 경영진 즉시 조치 사항 (3가지 이내, 우선순위 명확화)
- 언론/평판 리스크 평가

**인사이트 도출 지침:**
1. **근본 원인 분석**: 단순 증상이 아닌 근본 원인(Root Cause)을 깊이 있게 파악하세요
2. **Kill Chain 분석**: MITRE ATT&CK 프레임워크 기준으로 공격 단계를 분석하세요
3. **영향 범위**: 직접 영향과 간접 영향, 잠재적 확산 가능성을 명확히 구분하세요
4. **타임라인 재구성**: 최초 침투부터 탐지까지 정확한 타임라인을 재구성하세요
5. **유사 사례**: 과거 유사 사고나 알려진 캠페인과의 연관성을 분석하세요
6. **IOC 추출**: 파일 해시, IP, 도메인 등 구체적인 침해 지표를 제시하세요
7. **재발 방지**: 기술적/관리적/물리적 통제 개선 사항을 각각 제시하세요
8. **우선순위 대응**: 즉시(1시간), 긴급(24시간), 단기(1주), 중기(1개월)로 구분하여 조치사항을 제시하세요
9. **교훈 도출**: 이번 사고에서 얻은 교훈과 조직 차원의 개선점을 명확히 하세요
10. **법적 대응**: 신고 의무, 고객 통지, 규제 대응 등 법적 절차를 상세히 안내하세요"""
    }

    # 보고서 타입별 사용자 프롬프트 템플릿
    user_prompts = {
        'daily': f"""다음 일간 보안 관제 데이터를 분석하고 전문적인 보고서를 작성해주세요.

**📊 데이터 요약:**
{json.dumps(data_summary, ensure_ascii=False, indent=2)}

**📋 출력 양식 (반드시 준수):**

# 일간 보안 관제 보고서
**날짜:** {data_summary.get('date', 'N/A')}
**보고서 생성 시간:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**보고자:** 보안관제센터 수석 분석가

---

## 📌 Executive Summary (경영진 요약)

### 핵심 요약
*[1-2문장으로 당일 가장 중요한 내용을 경영진 관점에서 요약]*

### 비즈니스 임팩트 (재무적 관점)
- **차단한 위협의 예상 피해액:** ₩X,XXX,XXX
- **보안 시스템 방어 성과:** ₩X,XXX,XXX 손실 방지
- **누적 ROI:** 투자 대비 X배 효과

### 법적/규제 리스크
*[개인정보보호법, 정보통신망법 등 관련 법규 준수 현황 및 리스크]*

### 우선순위 조치사항
1. **[최우선]** *[즉시 실행 필요 사항]*
2. **[중요]** *[24시간 내 조치 필요]*
3. **[권고]** *[단기 개선 사항]*

---

## 📊 1. 탐지 현황

### 1.1 전체 통계
- **총 탐지 이벤트:** X건
- **랜섬웨어 의심:** X건 (전체의 X%)
- **정상 파일:** X건
- **평균 위험도:** X%

### 1.2 시간대별 분석
*[피크 시간대, 패턴 분석]*

### 1.3 위험도 분포
*[고위험/중위험/저위험 분류 및 해석]*

---

## 🚨 2. 주요 위협 분석

### 2.1 고위험 탐지 상세
*[랜섬웨어 의심 파일 상세 분석]*

### 2.2 공격 패턴 분석
*[유사 파일명, 공격 시간대 등 패턴 식별]*

### 2.3 위협 인텔리전스 연계
*[알려진 위협과의 유사성, IOC 매칭 결과]*

---

## 📈 3. 트렌드 비교
*[전일 대비, 주평균 대비 증감 분석]*

---

## ✅ 4. 조치 사항 및 권고

### 4.1 긴급 조치 (Immediate Actions)
*[즉시 실행해야 할 사항, 우선순위 1]*

### 4.2 단기 조치 (Short-term, 1-3일)
*[며칠 내 수행할 사항]*

### 4.3 중기 개선 (Mid-term, 1-2주)
*[시스템/정책 개선 사항]*

---

## 📌 5. 결론 및 종합 의견
*[전문가 관점의 종합 평가 및 향후 대응 방향]*

---

**보고서 종료**
*본 보고서는 AI 기반 분석을 통해 생성되었으며, 최종 검토는 보안 담당자가 수행해야 합니다.*
""",

        'weekly': f"""다음 주간 보안 관제 데이터를 분석하고 전문적인 보고서를 작성해주세요.

**📊 데이터 요약:**
{json.dumps(data_summary, ensure_ascii=False, indent=2)}

**📋 출력 양식 (반드시 준수):**

# 주간 보안 관제 보고서
**기간:** {data_summary.get('period', 'N/A')}
**보고서 생성 시간:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**보고자:** 보안관제센터 수석 분석가

---

## 📌 Executive Summary (경영진 요약)

### 핵심 요약
*[2-3문장으로 주간 가장 중요한 트렌드와 변화를 경영진 관점에서 요약]*

### 비즈니스 임팩트 (재무적 관점)
- **주간 차단 위협 총 예상 피해액:** ₩X,XXX,XXX
- **전주 대비 위험 증감:** +/-X% (₩X,XXX,XXX)
- **월간 누적 방어 성과:** ₩X,XXX,XXX
- **연간 예상 ROI:** 보안 투자 ₩XXX,XXX 대비 ₩X,XXX,XXX 손실 방지 (X배)

### 법적/규제 리스크 및 컴플라이언스
*[개인정보보호법, 정보통신망법, ISMS 인증 등 준수 현황 및 주요 리스크]*

### 경영진 의사결정 사항 (우선순위)
1. **[긴급]** *[차주 즉시 결정/승인 필요 사항]*
2. **[중요]** *[예산/인력 배분 관련]*
3. **[권고]** *[중기 전략적 개선 사항]*

---

## 📊 1. 주간 종합 현황

### 1.1 전체 통계
- **총 탐지 이벤트:** X건
- **랜섬웨어 의심:** X건 (X%)
- **정상 파일:** X건
- **일평균 탐지:** X건
- **평균 위험도:** X%

### 1.2 일별 추이 분석
*[요일별 패턴, 증감 추세 분석]*

### 1.3 주요 지표 변화
*[전주 대비 증감률, KPI 달성률]*

---

## 🚨 2. 주요 위협 분석

### 2.1 Top 위협 파일 (Top 5-10)
*[가장 많이 탐지된 파일 분석]*

### 2.2 공격 벡터 분석
*[공격 경로, 유입 채널 분석]*

### 2.3 위협 트렌드
*[새롭게 등장한 위협, 지속되는 위협]*

---

## 📈 3. 비교 분석

### 3.1 전주 대비 변화
*[증감 분석 및 원인 파악]*

### 3.2 월간 누적 현황
*[월간 목표 대비 진행 상황]*

### 3.3 산업 벤치마킹
*[유사 조직 대비 보안 수준 평가]*

---

## ✅ 4. 주간 대응 활동 성과

### 4.1 완료된 조치사항
*[지난주 권고사항 이행 현황]*

### 4.2 차단 성과
*[성공적으로 차단한 위협 통계]*

### 4.3 개선 사항
*[시스템/프로세스 개선 내역]*

---

## 🎯 5. 차주 권고 사항

### 5.1 우선순위 조치
*[다음 주 중점 과제]*

### 5.2 보안 정책 개선 제안
*[정책/절차 개선 권고]*

### 5.3 교육 및 인식 제고
*[사용자 교육 필요 영역]*

---

## 📌 6. 결론
*[주간 종합 평가 및 향후 전망]*

---

**보고서 종료**
""",

        'monthly': f"""다음 월간 보안 관제 데이터를 분석하고 전문적인 보고서를 작성해주세요.

**📊 데이터 요약:**
{json.dumps(data_summary, ensure_ascii=False, indent=2)}

**📋 출력 양식 (반드시 준수):**

# 월간 보안 관제 보고서
**기간:** {data_summary.get('period', 'N/A')}
**보고서 생성 시간:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**보고자:** 보안관제센터 수석 분석가 / CISO 자문위원

---

## 📌 Executive Summary (경영진 요약)

### 이사회 보고용 한 문장 요약
*[월간 보안 현황을 이사회 수준에서 가장 중요한 한 문장으로 요약]*

### 핵심 요약
*[3-4문장으로 월간 핵심 성과, 주요 위협, 전략적 제언을 경영진 관점에서 요약]*

### 비즈니스 임팩트 (재무적 관점)
- **월간 총 차단 위협 예상 피해액:** ₩XX,XXX,XXX
- **전월 대비 위험 증감:** +/-X% (₩X,XXX,XXX)
- **연간 누적 방어 성과:** ₩XXX,XXX,XXX
- **보안 시스템 연간 ROI:** 투자 ₩X,XXX,XXX 대비 ₩XXX,XXX,XXX 방어 (XX배)
- **예상 보험료 절감 효과:** ₩X,XXX,XXX/년

### 법적 책임 및 규제 준수 현황
- **개인정보보호법 준수:** [적합/주의/위험]
- **정보통신망법 준수:** [적합/주의/위험]
- **ISMS 인증 현황:** [유지/갱신필요/미인증]
- **법적 신고 의무 사항:** [없음/진행중/완료]

### 차월 예산 및 자원 배분 권고
- **우선 투자 영역:** *[구체적 항목]*
- **권장 예산:** ₩X,XXX,XXX
- **예상 효과:** *[정량적 목표]*

### 경영진 전략적 의사결정 사항
1. **[이사회 승인 필요]** *[중대 의사결정 사항]*
2. **[긴급 예산 승인]** *[예산 배정 필요 사항]*
3. **[정책 변경]** *[조직 차원 정책 개선]*

---

## 📊 1. 월간 종합 현황

### 1.1 핵심 지표 (KPI)
- **총 탐지 이벤트:** X건
- **랜섬웨어 탐지:** X건 (X%)
- **일평균 탐지:** X건
- **평균 위험도:** X%
- **탐지 정확도:** X%

### 1.2 주별 추이 분석
*[주차별 패턴 및 트렌드]*

### 1.3 월간 목표 달성률
*[KPI 달성 현황 및 분석]*

---

## 🚨 2. 위협 심층 분석

### 2.1 Top 위협 파일 (Top 10)
*[가장 위험한 파일 및 재출현 파일 분석]*

### 2.2 공격 시나리오 분석
*[Kill Chain 단계별 분석]*

### 2.3 시간대/요일별 패턴
*[공격 타이밍 패턴 분석]*

### 2.4 위협 인텔리전스 매칭
*[외부 위협 정보와의 상관관계]*

---

## 📈 3. 비교 분석 및 벤치마킹

### 3.1 전월 대비 분석
*[월간 증감 추세 및 원인]*

### 3.2 연간 누적 현황
*[연간 목표 대비 진행률]*

### 3.3 산업 평균 비교
*[동종 업계 보안 수준 비교]*

---

## 💰 4. 보안 투자 효과 분석 (ROI)

### 4.1 차단 성과 정량화
*[차단한 위협의 잠재적 피해액 추정]*

### 4.2 비용 대비 효과
*[보안 투자 대비 방어 성과]*

### 4.3 리소스 활용도
*[인력, 시스템 자원 활용 효율성]*

---

## ✅ 5. 월간 대응 활동 및 개선 사항

### 5.1 완료된 프로젝트
*[보안 강화 프로젝트 성과]*

### 5.2 시스템 고도화
*[탐지 시스템 개선 내역]*

### 5.3 프로세스 개선
*[운영 효율화 사항]*

---

## 🎯 6. 차월 전략 및 권고

### 6.1 전략적 우선순위
*[다음 달 중점 추진 과제]*

### 6.2 예산 및 자원 배분 권고
*[투자 우선순위 및 예산 제안]*

### 6.3 정책 및 제도 개선
*[규정, 프로세스 개선 권고]*

### 6.4 조직 역량 강화
*[교육, 훈련, 인력 충원 계획]*

---

## 📌 7. 규제 준수 및 컴플라이언스

### 7.1 법적 요구사항 준수 현황
*[개인정보보호법, 정보통신망법 등]*

### 7.2 인증/감사 대응
*[ISO 27001, ISMS 등]*

---

## 📌 8. 종합 결론 및 CISO 의견
*[월간 종합 평가, 리스크 수준, 향후 3개월 전망]*

---

**보고서 종료**
""",

        'incident': f"""다음 사고 정보를 분석하고 전문적인 사고 대응 보고서를 작성해주세요.

**📊 사고 데이터:**
{json.dumps(data_summary, ensure_ascii=False, indent=2)}

**📋 출력 양식 (반드시 준수):**

# 사고 대응 보고서 (Incident Response Report)
**사고 ID:** {data_summary.get('incident_id', 'N/A')}
**탐지 시간:** {data_summary.get('detected_at', 'N/A')}
**보고서 생성 시간:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**보고자:** 사이버 사고 대응팀 (CSIRT)

---

## 🚨 사고 개요 (Executive Summary)

### 긴급 요약
*[사고의 핵심 내용을 경영진이 즉시 이해할 수 있도록 2-3문장으로 요약]*

### 재무적 영향 (한국 원화)
- **실제 피해액:** ₩X,XXX,XXX (실행되었을 경우) / ₩0 (차단 성공)
- **복구 예상 비용:** ₩X,XXX,XXX
- **업무 중단 손실:** ₩X,XXX,XXX (예상 X시간 중단)
- **보안 시스템 ROI 기여:** ₩XX,XXX,XXX 손실 방지

### 법적/규제 대응
- **신고 의무:** [있음/없음]
  - 개인정보보호위원회: [신고완료/신고예정/해당없음]
  - KISA (한국인터넷진흥원): [신고완료/신고예정/해당없음]
- **법적 책임 리스크:** [높음/중간/낮음]
- **규제 위반 가능성:** *[구체적 법규 및 조항]*

### 비즈니스 중단 영향
- **영향받은 부서/시스템:** *[구체적 명시]*
- **복구 소요 시간:** 예상 X시간/X일
- **업무 재개 시점:** [즉시/X시간 후/X일 후]

### 평판 및 언론 리스크
- **외부 공개 필요성:** [있음/없음/검토중]
- **언론 대응 필요성:** [긴급/주의/없음]
- **고객 공지 필요성:** [필수/권장/불필요]

### 경영진 즉시 조치 사항 (우선순위)
1. **[최긴급]** *[즉각 실행 필요 - 담당자 지정]*
2. **[긴급]** *[24시간 내 의사결정 필요]*
3. **[중요]** *[48시간 내 승인 필요]*

---

## 📋 1. 사고 기본 정보

| 항목 | 내용 |
|------|------|
| **사고 ID** | {data_summary.get('incident_id', 'N/A')} |
| **파일명** | `{data_summary.get('file_name', 'N/A')}` |
| **탐지 시간** | {data_summary.get('detected_at', 'N/A')} |
| **위험도** | {data_summary.get('risk_level', 'N/A')} |
| **현재 상태** | {data_summary.get('status', 'N/A')} |
| **담당자** | {data_summary.get('assigned_to', 'N/A')} |

---

## 🔍 2. 위협 분석

### 2.1 악성코드 분석 결과
- **탐지 확률:** X%
- **분류:** 랜섬웨어 / 기타 악성코드
- **위협 등급:** Critical / High / Medium / Low

### 2.2 이상 징후 (Anomalies)
*[탐지된 이상 특성 나열 및 해석]*

### 2.3 IOC (Indicators of Compromise)
*[파일 해시, 파일명 패턴, 행위 특성 등]*

### 2.4 유사 사례 분석
*[과거 유사 사고, 알려진 캠페인과의 연관성]*

---

## 📍 3. 영향 범위 평가

### 3.1 직접 영향
*[감염된 시스템, 파일 목록]*

### 3.2 잠재적 영향
*[확산 가능성, 2차 피해 우려]*

### 3.3 비즈니스 임팩트
*[업무 중단, 데이터 유출, 재정적 영향]*

---

## ⚡ 4. 대응 조치 타임라인

### 4.1 Preparation (사전 준비)
- [타임스탬프] 보안 시스템 정상 가동 확인

### 4.2 Detection & Analysis (탐지 및 분석)
- [타임스탬프] 랜섬웨어 의심 파일 탐지
- [타임스탬프] 초기 분석 완료

### 4.3 Containment (격리)
- [타임스탬프] 의심 파일 격리 조치
- [타임스탬프] 네트워크 차단 (필요시)

### 4.4 Eradication (제거)
- [타임스탬프] 악성코드 완전 제거

### 4.5 Recovery (복구)
- [타임스탬프] 시스템 복구 절차 진행
- [타임스탬프] 정상 운영 재개

### 4.6 Lessons Learned (교훈 도출)
- [예정] 사후 검토 회의 일정

---

## ✅ 5. 완료된 조치사항
*[체크리스트 형식으로 완료된 대응 단계 정리]*

---

## 🎯 6. 향후 조치 계획

### 6.1 즉시 조치 (24시간 이내)
*[긴급 대응 사항]*

### 6.2 단기 조치 (1주일 이내)
*[재발 방지를 위한 긴급 패치]*

### 6.3 중기 개선 (1개월 이내)
*[시스템/정책 강화 계획]*

---

## 🔐 7. 재발 방지 권고사항

### 7.1 기술적 통제
*[방화벽, EDR, 백업 등]*

### 7.2 관리적 통제
*[정책, 절차, 권한 관리]*

### 7.3 사용자 교육
*[보안 인식 제고 방안]*

---

## 📌 8. 법적/규제적 고려사항
*[개인정보 유출 여부, 신고 의무, 규제 대응]*

---

## 📌 9. 종합 의견 및 권고
*[CSIRT 팀장 의견, 경영진 보고사항, 향후 대응 방향]*

---

**보고서 종료**
*본 사고는 [해결/진행중] 상태이며, 추가 업데이트 시 본 보고서가 갱신됩니다.*
"""
    }

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # GPT-4o Mini 모델 사용 (빠르고 효율적)
            messages=[
                {"role": "system", "content": system_prompts.get(report_type, system_prompts['daily'])},
                {"role": "user", "content": user_prompts.get(report_type, user_prompts['daily'])}
            ],
            temperature=0.7,  # 창의성과 일관성의 균형
            max_tokens=4000,  # 긴 보고서를 위한 충분한 토큰
            top_p=0.9,
            frequency_penalty=0.3,  # 반복 감소
            presence_penalty=0.3   # 다양한 표현 장려
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"⚠️ AI 보고서 생성 중 오류 발생: {str(e)}\n\n기본 보고서 형식으로 대체합니다."

# --- 13. 보고서 생성 시스템 (AI 강화 버전) ---
def generate_daily_report(target_date=None, use_ai=True):
    """일간 보고서 생성 (AI 기반)"""
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
    ransomware_count = int((daily_df['label'] == 1).sum())
    benign_count = int((daily_df['label'] == 0).sum())
    avg_prob = float(daily_df['probability'].mean()) if 'probability' in daily_df.columns else 0.0

    # 시간대별 통계
    hourly_stats = daily_df.groupby(daily_df['timestamp'].dt.hour).size()
    hourly_data = {f"{int(hour):02d}:00": int(count) for hour, count in hourly_stats.items()}

    # 랜섬웨어 상세 정보
    ransomware_details = []
    if ransomware_count > 0:
        ransomware_events = daily_df[daily_df['label'] == 1]
        for idx, row in ransomware_events.iterrows():
            ransomware_details.append({
                "file_name": row['file_name'],
                "file_path": str(row['file_path']),
                "detected_time": row['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                "probability": float(row.get('probability', 0)),
                "action": str(row.get('action_result', 'N/A'))
            })

    # AI 보고서 생성용 데이터 요약
    data_summary = {
        "date": date_str,
        "total_events": total_events,
        "ransomware_count": ransomware_count,
        "benign_count": benign_count,
        "avg_probability": avg_prob,
        "hourly_distribution": hourly_data,
        "ransomware_details": ransomware_details
    }

    # AI를 사용한 보고서 생성
    if use_ai:
        report_content = generate_ai_report('daily', data_summary)
    else:
        # 기본 템플릿 사용 (폴백)
        report_content = f"""# 일간 보안 관제 보고서
**날짜:** {date_str}
**생성 시간:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 요약
- 총 탐지: {total_events}건
- 랜섬웨어: {ransomware_count}건
- 정상: {benign_count}건
- 평균 위험도: {avg_prob:.2%}
"""

    # 파일 저장
    report_path = report_dir / f"daily_report_{date_str}.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_content)

    return report_path

def generate_weekly_report(target_week=None, use_ai=True):
    """주간 보고서 생성 (AI 기반)"""
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
    ransomware_count = int((weekly_df['label'] == 1).sum())
    benign_count = int((weekly_df['label'] == 0).sum())
    avg_prob = float(weekly_df['probability'].mean()) if 'probability' in weekly_df.columns else 0.0

    # 일별 통계
    daily_stats = weekly_df.groupby(weekly_df['timestamp'].dt.date).agg({
        'label': ['count', ('ransomware', lambda x: (x == 1).sum())]
    })

    daily_data = {}
    for date_val, row in daily_stats.iterrows():
        daily_data[str(date_val)] = {
            "total": int(row[('label', 'count')]),
            "ransomware": int(row[('label', 'ransomware')]),
            "benign": int(row[('label', 'count')] - row[('label', 'ransomware')])
        }

    # Top 파일 통계
    top_files = []
    if ransomware_count > 0:
        ransomware_events = weekly_df[weekly_df['label'] == 1]
        file_counts = ransomware_events['file_name'].value_counts()
        top_files = [{"file_name": str(name), "count": int(count)} for name, count in file_counts.head(5).items()]

    # AI 보고서 생성용 데이터 요약
    data_summary = {
        "period": f"{year}년 {week_num}주차",
        "week_string": week_str,
        "total_events": total_events,
        "ransomware_count": ransomware_count,
        "benign_count": benign_count,
        "avg_probability": avg_prob,
        "daily_average": round(total_events / 7, 1),
        "daily_stats": daily_data,
        "top_files": top_files
    }

    # AI를 사용한 보고서 생성
    if use_ai:
        report_content = generate_ai_report('weekly', data_summary)
    else:
        # 기본 템플릿
        report_content = f"""# 주간 보안 관제 보고서
**기간:** {week_str}
**생성 시간:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 요약
- 총 탐지: {total_events}건
- 랜섬웨어: {ransomware_count}건
"""

    # 파일 저장
    report_path = report_dir / f"weekly_report_{week_str}.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_content)

    return report_path

def generate_monthly_report(target_month=None, use_ai=True):
    """월간 보고서 생성 (AI 기반)"""
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
    ransomware_count = int((monthly_df['label'] == 1).sum())
    benign_count = int((monthly_df['label'] == 0).sum())
    avg_prob = float(monthly_df['probability'].mean()) if 'probability' in monthly_df.columns else 0.0

    # 주별 통계
    weekly_stats = monthly_df.groupby(monthly_df['timestamp'].dt.isocalendar().week).agg({
        'label': ['count', ('ransomware', lambda x: (x == 1).sum())]
    })

    weekly_data = {}
    for week, row in weekly_stats.iterrows():
        weekly_data[f"{int(week)}주차"] = {
            "total": int(row[('label', 'count')]),
            "ransomware": int(row[('label', 'ransomware')]),
            "benign": int(row[('label', 'count')] - row[('label', 'ransomware')])
        }

    # Top 파일 및 시간대 분석
    top_files = []
    peak_hour = None
    if ransomware_count > 0:
        ransomware_events = monthly_df[monthly_df['label'] == 1]
        file_counts = ransomware_events['file_name'].value_counts()
        top_files = [{"file_name": str(name), "count": int(count)} for name, count in file_counts.head(10).items()]

        hourly_distribution = ransomware_events.groupby(ransomware_events['timestamp'].dt.hour).size()
        peak_hour = int(hourly_distribution.idxmax())

    # AI 보고서 생성용 데이터 요약
    data_summary = {
        "period": f"{year}년 {month}월",
        "month_string": month_str,
        "total_events": total_events,
        "ransomware_count": ransomware_count,
        "benign_count": benign_count,
        "avg_probability": avg_prob,
        "daily_average": round(total_events / 30, 1),
        "weekly_stats": weekly_data,
        "top_files": top_files,
        "peak_hour": peak_hour
    }

    # AI를 사용한 보고서 생성
    if use_ai:
        report_content = generate_ai_report('monthly', data_summary)
    else:
        # 기본 템플릿
        report_content = f"""# 월간 보안 관제 보고서
**기간:** {month_str}
**생성 시간:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 요약
- 총 탐지: {total_events}건
- 랜섬웨어: {ransomware_count}건
"""

    # 파일 저장
    report_path = report_dir / f"monthly_report_{month_str}.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_content)

    return report_path

def generate_incident_report(incident):
    """사고 보고서 생성 (AI 기반)"""
    incident_id = incident['incident_id']
    file_name_safe = incident['file_name'].replace('/', '_').replace('\\', '_')
    report_dir = REPORTS_DIR / "incidents" / f"{incident_id}_{file_name_safe}"
    os.makedirs(report_dir, exist_ok=True)

    # 사고 데이터 요약 준비
    data_summary = {
        'incident_id': incident_id,
        'file_name': incident['file_name'],
        'file_path': incident['file_path'],
        'detected_at': incident['created_at'],
        'probability': f"{incident['probability']:.2%}",
        'priority': incident['priority'],
        'assigned_to': incident['assigned_to'],
        'status': incident['status'],
        'timeline': incident['timeline'],
        'checklist': incident['checklist'],
        'risk_level': '고위험' if incident['probability'] >= 0.8 else '중위험' if incident['probability'] >= 0.5 else '저위험'
    }

    # AI로 보고서 생성
    try:
        ai_report = generate_ai_report('incident', data_summary)
        report_content = ai_report

        # AI 생성 실패 시 기본 템플릿 사용
        if not ai_report or "OpenAI API 키가 설정되지 않았습니다" in ai_report or "오류" in ai_report:
            raise Exception("AI 보고서 생성 실패")

    except Exception as e:
        # 폴백: 기본 템플릿 사용
        st.warning(f"⚠️ AI 보고서 생성 실패: {str(e)}\n기본 템플릿으로 대체합니다.")

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
