"""
Real-time Threat Detection Simulation Dashboard
This dashboard simulates real-time log analysis and visualizes the results.
"""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import os
import time
import random
from datetime import datetime
import geoip2.database
from geolite2 import geolite2
import pydeck as pdk

# Import the copied log analyzer
from sim_log_analyzer_v2 import LogAnalyzer

# --- Initial Page Configuration ---
st.set_page_config(
    page_title="실시간 위협 탐지 시뮬레이션",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Constants and Directories ---
SIMULATION_FILE = "Mini_PJT2/simulation_log.csv"
OUTPUT_DIR = "output_analysis"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- Caching Functions ---
@st.cache_resource
def load_analyzer():
    """Load the log analysis engine (cached)."""
    return LogAnalyzer()

@st.cache_resource
def load_simulation_data():
    """Load the simulation log file."""
    if os.path.exists(SIMULATION_FILE):
        return pd.read_csv(SIMULATION_FILE)
    else:
        st.error(f"시뮬레이션 파일 '{SIMULATION_FILE}'을 찾을 수 없습니다.")
        return None

@st.cache_resource
def get_geoip_reader():
    """Get a GeoIP2 reader object."""
    try:
        # geolite2 will download the DB if it doesn't exist
        reader = geolite2.reader()
        return reader
    except Exception as e:
        st.warning(f"GeoIP 데이터베이스를 로드할 수 없습니다: {e}")
        return None

# --- Helper Functions ---
def get_ip_info(ip: str):
    """Get geolocation info for an IP address."""
    reader = get_geoip_reader()
    if not reader or not ip or pd.isna(ip):
        return None

    try:
        # Check for private IP addresses
        if ip.startswith(('10.', '172.', '192.168.')):
            return None
        
        response = reader.get(ip)
        if response and 'location' in response:
            loc = response['location']
            return {
                "latitude": loc.get('latitude'),
                "longitude": loc.get('longitude'),
                "country": response.get('country', {}).get('names', {}).get('en', 'Unknown'),
                "city": response.get('city', {}).get('names', {}).get('en', 'Unknown')
            }
    except geoip2.errors.AddressNotFoundError:
        return None # IP not found in the database
    except Exception:
        return None # Other errors
    return None

# --- Session State Initialization ---
def initialize_session_state():
    """Initialize all necessary session state variables."""
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = load_analyzer()
    if 'simulation_df' not in st.session_state:
        st.session_state.simulation_df = load_simulation_data()
    
    # Simulation control
    if 'simulation_running' not in st.session_state:
        st.session_state.simulation_running = False
    if 'log_index' not in st.session_state:
        st.session_state.log_index = 0

    # Data storage
    if 'results_df' not in st.session_state:
        st.session_state.results_df = pd.DataFrame()
    if 'attack_locations' not in st.session_state:
        st.session_state.attack_locations = pd.DataFrame(columns=['latitude', 'longitude', 'attack_type', 'timestamp'])

    # Chart data
    if 'time_series_data' not in st.session_state:
        st.session_state.time_series_data = []

# Initialize the session state
initialize_session_state()


# --- UI Components ---
st.title("📡 실시간 위협 탐지 시뮬레이션")
st.markdown("---")

# Sidebar Controls
with st.sidebar:
    st.header("⚙️ 시뮬레이션 제어")
    
    start_stop_button = st.button("시뮬레이션 시작/중지", type="primary")
    if start_stop_button:
        st.session_state.simulation_running = not st.session_state.simulation_running
        if not st.session_state.simulation_running:
            st.info("시뮬레이션이 중지되었습니다.")
        else:
            st.info("시뮬레이션 시작!")

    if st.button("결과 초기화"):
        st.session_state.log_index = 0
        st.session_state.results_df = pd.DataFrame()
        st.session_state.attack_locations = pd.DataFrame(columns=['latitude', 'longitude', 'attack_type', 'timestamp'])
        st.session_state.time_series_data = []
        st.session_state.simulation_running = False
        st.success("모든 결과가 초기화되었습니다.")
        st.rerun()

    st.markdown("---")
    speed = st.slider("시뮬레이션 속도 (초당 로그 수)", 1, 20, 5)
    sleep_interval = 1 / speed

    st.markdown("---")
    st.header("ℹ️ 시스템 정보")
    if st.session_state.analyzer:
        st.success("✅ 분석 엔진 준비 완료")
        st.metric("벡터 DB 크기", f"{st.session_state.analyzer.vectordb.index.ntotal:,}개")
    else:
        st.error("❌ 분석 엔진 로드 실패")
    
    if st.session_state.simulation_df is not None:
        st.metric("시뮬레이션 로그", f"{len(st.session_state.simulation_df):,}개")

# Main Dashboard Layout
st.header("🔴 실시간 탐지 현황")

# Placeholders for dynamic content
metrics_placeholder = st.empty()
chart_placeholder = st.empty()
map_placeholder = st.empty()
table_placeholder = st.empty()

# --- Simulation Loop ---
if st.session_state.simulation_running:
    if st.session_state.simulation_df is not None and st.session_state.analyzer is not None:
        
        # Get current log
        log_idx = st.session_state.log_index
        if log_idx < len(st.session_state.simulation_df):
            
            current_log_row = st.session_state.simulation_df.iloc[log_idx]
            
            # Analyze the log
            analyzer = st.session_state.analyzer
            row_text = analyzer.row_to_text(current_log_row)
            analysis_result = analyzer.analyze_single_row(row_text, top_k=5)
            
            # Combine original log with analysis result
            now = datetime.now()
            result_series = pd.Series(analysis_result)
            result_series['timestamp'] = now
            # Use 'Source IP' for geolocation
            result_series['ip_address'] = current_log_row.get('Source IP')
            
            # Append to results DataFrame
            new_result_df = pd.DataFrame([result_series])
            st.session_state.results_df = pd.concat([st.session_state.results_df, new_result_df], ignore_index=True)
            
            # Update time series data for the line chart
            malware_count = st.session_state.results_df['is_malware'].sum()
            benign_count = len(st.session_state.results_df) - malware_count
            st.session_state.time_series_data.append({'time': result_series['timestamp'], 'malware': malicious, 'benign': total - malicious})

            # If malware is detected, get location and add to map data
            if analysis_result['is_malware']:
                ip_info = get_ip_info(result_series['ip_address'])
                if ip_info and ip_info['latitude'] is not None:
                    new_location = pd.DataFrame([{
                        'latitude': ip_info['latitude'],
                        'longitude': ip_info['longitude'],
                        'attack_type': analysis_result['attack_type'],
                        'timestamp': now
                    }])
                    st.session_state.attack_locations = pd.concat([st.session_state.attack_locations, new_location], ignore_index=True)

            # --- Update UI Placeholders ---
            with metrics_placeholder.container():
                total_logs = len(st.session_state.results_df)
                malware_detected = st.session_state.results_df['is_malware'].sum()
                benign_detected = total_logs - malware_detected
                malware_ratio = (malware_detected / total_logs * 100) if total_logs > 0 else 0

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("총 처리 로그", f"{total_logs:,} 개")
                col2.metric("정상 로그", f"{benign_detected:,} 개")
                col3.metric("악성 로그", f"{malware_detected:,} 개", delta=f"{malware_ratio:.1f}%", delta_color="inverse")
                col4.metric("평균 확신도", f"{st.session_state.results_df['confidence'].mean():.2%}")

            with chart_placeholder.container():
                ts_df = pd.DataFrame(st.session_state.time_series_data)
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=ts_df['time'], y=ts_df['malware'], mode='lines', name='악성', line=dict(color='red')))
                fig.add_trace(go.Scatter(x=ts_df['time'], y=ts_df['benign'], mode='lines', name='정상', line=dict(color='green')))
                fig.update_layout(title="시간에 따른 탐지 추이", xaxis_title="시간", yaxis_title="누적 로그 수")
                st.plotly_chart(fig, use_container_width=True)

            with map_placeholder.container():
                st.subheader("🌍 실시간 공격 발원지")
                locations = st.session_state.attack_locations
                if not locations.empty:
                    st.pydeck_chart(pdk.Deck(
                        map_style='mapbox://styles/mapbox/dark-v9',
                        initial_view_state=pdk.ViewState(
                            latitude=20,
                            longitude=0,
                            zoom=1,
                            pitch=50,
                        ),
                        layers=[
                            pdk.Layer(
                                'HexagonLayer',
                                data=locations,
                                get_position='[longitude, latitude]',
                                radius=100000,
                                elevation_scale=4,
                                elevation_range=[0, 1000],
                                pickable=True,
                                extruded=True,
                            ),
                        ],
                        tooltip={"text": "공격 유형: {attack_type}\n시간: {timestamp}"}
                    ))
                else:
                    st.info("아직 탐지된 공격 위치가 없습니다. 지도는 공격이 탐지되면 업데이트됩니다.")

            with table_placeholder.container():
                st.subheader("🚨 최신 악성 탐지 로그")
                malicious_df = st.session_state.results_df[st.session_state.results_df['is_malware']].copy()
                malicious_df['timestamp'] = pd.to_datetime(malicious_df['timestamp']).dt.strftime('%H:%M:%S')
                st.dataframe(
                    malicious_df[['timestamp', 'attack_type', 'confidence', 'ip_address']].tail(10).sort_index(ascending=False),
                    use_container_width=True,
                    hide_index=True
                )

            # Increment log index and sleep
            st.session_state.log_index += 1
            time.sleep(sleep_interval)
            st.rerun()
            
        else:
            st.success("🎉 시뮬레이션 완료! 모든 로그를 처리했습니다.")
            st.session_state.simulation_running = False
            # Save final results
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(OUTPUT_DIR, f"simulation_result_{timestamp}.csv")
            st.session_state.results_df.to_csv(output_path, index=False)
            st.info(f"최종 결과가 {output_path}에 저장되었습니다.")

# Show initial state if not running
if not st.session_state.simulation_running and st.session_state.results_df.empty:
    st.info("사이드바에서 '시뮬레이션 시작/중지' 버튼을 눌러 실시간 탐지를 시작하세요.")

# Show final state
elif not st.session_state.simulation_running and not st.session_state.results_df.empty:
    st.info("시뮬레이션이 중지되었습니다. '결과 초기화' 또는 '시뮬레이션 시작/중지' 버튼을 눌러 다시 시작할 수 있습니다.")
    # Display final state
    total_logs = len(st.session_state.results_df)
    malware_detected = st.session_state.results_df['is_malware'].sum()
    benign_detected = total_logs - malware_detected
    malware_ratio = (malware_detected / total_logs * 100) if total_logs > 0 else 0

    with metrics_placeholder.container():
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("총 처리 로그", f"{total_logs:,} 개")
        col2.metric("정상 로그", f"{benign_detected:,} 개")
        col3.metric("악성 로그", f"{malware_detected:,} 개", delta=f"{malware_ratio:.1f}%", delta_color="inverse")
        col4.metric("평균 확신도", f"{st.session_state.results_df['confidence'].mean():.2%}")

    with chart_placeholder.container():
        ts_df = pd.DataFrame(st.session_state.time_series_data)
        if not ts_df.empty:
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=ts_df['time'], y=ts_df['malware'], mode='lines', name='악성', line=dict(color='red')))
            fig.add_trace(go.Scatter(x=ts_df['time'], y=ts_df['benign'], mode='lines', name='정상', line=dict(color='green')))
            fig.update_layout(title="시간에 따른 탐지 추이", xaxis_title="시간", yaxis_title="누적 로그 수")
            st.plotly_chart(fig, use_container_width=True)

    with map_placeholder.container():
        st.subheader("🌍 최종 공격 발원지 맵")
        locations = st.session_state.attack_locations
        if not locations.empty:
            st.pydeck_chart(pdk.Deck(
                map_style='mapbox://styles/mapbox/dark-v9',
                initial_view_state=pdk.ViewState(latitude=20, longitude=0, zoom=1, pitch=50),
                layers=[pdk.Layer('HexagonLayer', data=locations, get_position='[longitude, latitude]', radius=100000, elevation_scale=4, elevation_range=[0, 1000], pickable=True, extruded=True)],
                tooltip={"text": "공격 유형: {attack_type}\n시간: {timestamp}"}
            ))

    with table_placeholder.container():
        st.subheader("🚨 최종 악성 탐지 로그 (최신 10건)")
        malicious_df = st.session_state.results_df[st.session_state.results_df['is_malware']].copy()
        if not malicious_df.empty:
            malicious_df['timestamp'] = pd.to_datetime(malicious_df['timestamp']).dt.strftime('%H:%M:%S')
            st.dataframe(
                malicious_df[['timestamp', 'attack_type', 'confidence', 'ip_address']].tail(10).sort_index(ascending=False),
                use_container_width=True,
                hide_index=True
            )
