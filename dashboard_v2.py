"""
Dashboard v2 - 랜섬웨어 탐지 시스템
log_analyzer_v2.py와 연동하여 로그 분석 및 시각화
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import time
from datetime import datetime
from streamlit_float import float_init, float_css_helper
from openai import OpenAI
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

# log_analyzer_v2 임포트
from log_analyzer_v2 import LogAnalyzer

# 페이지 설정
st.set_page_config(
    page_title="랜섬웨어 탐지 대시보드",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 디렉토리 설정
UPLOAD_DIR = "uploads"
OUTPUT_DIR = "output_analysis"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 세션 상태 초기화
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = None
if 'analysis_result' not in st.session_state:
    st.session_state.analysis_result = None
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'show_chatbot' not in st.session_state:
    st.session_state.show_chatbot = False
if 'openai_api_key' not in st.session_state:
    st.session_state.openai_api_key = os.getenv('OPENAI_API_KEY', '')


@st.cache_resource
def load_analyzer():
    """로그 분석 엔진 로드 (캐싱)"""
    return LogAnalyzer()


def create_pie_chart(summary):
    """악성/정상 비율 파이 차트"""
    fig = go.Figure(data=[go.Pie(
        labels=['악성 로그', '정상 로그'],
        values=[summary['malware_detected'], summary['benign_detected']],
        hole=0.4,
        marker=dict(colors=['#FF6B6B', '#51CF66']),
        textinfo='label+percent+value',
        textfont=dict(size=14)
    )])

    fig.update_layout(
        title=dict(
            text=f"악성/정상 비율 (총 {summary['total_logs']:,}개)",
            font=dict(size=20)
        ),
        height=400,
        showlegend=True
    )

    return fig


def create_attack_distribution_chart(summary):
    """공격 유형별 분포 막대 그래프"""
    attack_stats = summary['attack_stats']

    attack_types = list(attack_stats.keys())
    counts = [stats['count'] for stats in attack_stats.values()]
    confidences = [stats['avg_confidence'] * 100 for stats in attack_stats.values()]

    # 색상 매핑 (공격 유형별)
    colors = []
    for attack_type in attack_types:
        if 'Ransomware' in attack_type:
            colors.append('#FF6B6B')  # 빨강
        elif 'Normal' in attack_type or 'Benign' in attack_type:
            colors.append('#51CF66')  # 초록
        else:
            colors.append('#FFA94D')  # 주황

    fig = go.Figure(data=[
        go.Bar(
            x=attack_types,
            y=counts,
            text=counts,
            textposition='outside',
            marker=dict(color=colors),
            hovertemplate='<b>%{x}</b><br>탐지: %{y}개<br><extra></extra>'
        )
    ])

    fig.update_layout(
        title=dict(
            text="공격 유형별 탐지 분포",
            font=dict(size=20)
        ),
        xaxis_title="공격 유형",
        yaxis_title="탐지 횟수",
        height=400,
        showlegend=False
    )

    return fig


def create_confidence_histogram(df):
    """확신도 분포 히스토그램"""
    fig = px.histogram(
        df,
        x='confidence',
        nbins=30,
        title='확신도 분포',
        labels={'confidence': '확신도', 'count': '빈도'},
        color_discrete_sequence=['#4DABF7']
    )

    fig.update_layout(
        height=400,
        xaxis_title='확신도',
        yaxis_title='빈도',
        title_font_size=20
    )

    return fig


def create_attack_confidence_chart(summary):
    """공격 유형별 평균 확신도"""
    attack_stats = summary['attack_stats']

    attack_types = list(attack_stats.keys())
    confidences = [stats['avg_confidence'] * 100 for stats in attack_stats.values()]

    fig = go.Figure(data=[
        go.Bar(
            x=attack_types,
            y=confidences,
            text=[f"{c:.1f}%" for c in confidences],
            textposition='outside',
            marker=dict(color='#845EF7'),
            hovertemplate='<b>%{x}</b><br>확신도: %{y:.1f}%<br><extra></extra>'
        )
    ])

    fig.update_layout(
        title=dict(
            text="공격 유형별 평균 확신도",
            font=dict(size=20)
        ),
        xaxis_title="공격 유형",
        yaxis_title="평균 확신도 (%)",
        height=400,
        showlegend=False
    )

    return fig


# ========== 메인 UI ==========

st.title("🛡️ AI 기반 랜섬웨어 탐지 시스템")
st.markdown("---")

# 사이드바
with st.sidebar:
    st.header("⚙️ 설정")

    # 샘플링 설정
    use_sampling = st.checkbox("샘플링 사용 (빠른 분석)", value=True)
    if use_sampling:
        sample_size = st.slider("샘플 크기", 100, 5000, 1000, 100)
    else:
        sample_size = None
        st.warning("전체 분석은 시간이 오래 걸릴 수 있습니다.")

    st.markdown("---")

    st.header("📊 시스템 정보")
    if st.session_state.analyzer is None:
        st.info("분석 엔진 대기 중...")
    else:
        st.success("✅ 분석 엔진 준비 완료")
        st.metric("벡터 DB 크기", "500,000개")

    st.markdown("---")

    # 분석 기록
    st.header("📁 분석 기록")
    analysis_files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith('_analyzed.csv')]
    if analysis_files:
        st.write(f"총 {len(analysis_files)}개 분석 완료")
        selected_file = st.selectbox("이전 분석 불러오기", [""] + analysis_files)
        if selected_file and st.button("불러오기"):
            loaded_df = pd.read_csv(os.path.join(OUTPUT_DIR, selected_file))

            # 불러온 DataFrame으로부터 요약 생성
            if st.session_state.analyzer is None:
                st.session_state.analyzer = load_analyzer()

            analyzer = st.session_state.analyzer
            summary = analyzer.generate_summary(loaded_df, [])

            st.session_state.analysis_result = {
                'df': loaded_df,
                'summary': summary,
                'elapsed_time': 0,
                'output_path': os.path.join(OUTPUT_DIR, selected_file)
            }
            st.success(f"✅ {selected_file} 불러오기 완료!")
            st.rerun()
    else:
        st.info("분석 기록이 없습니다.")


# 메인 컨텐츠
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("📤 CSV 파일 업로드")
    uploaded_file = st.file_uploader(
        "네트워크 로그 CSV 파일을 업로드하세요",
        type=['csv'],
        help="UNSW-NB15, CIC-AndMal2017 등의 네트워크 로그 파일"
    )

with col2:
    st.subheader("🎯 분석 실행")
    analyze_button = st.button(
        "🔍 분석 시작",
        disabled=(uploaded_file is None),
        type="primary",
        width='stretch'
    )

# 분석 실행
if analyze_button and uploaded_file is not None:
    # 분석 엔진 로드
    if st.session_state.analyzer is None:
        with st.spinner("분석 엔진 초기화 중..."):
            try:
                st.session_state.analyzer = load_analyzer()
            except Exception as e:
                st.error(f"❌ 분석 엔진 로드 실패: {e}")
                st.stop()

    # 파일 저장
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_file_path = os.path.join(UPLOAD_DIR, f"{timestamp}_{uploaded_file.name}")

    with open(temp_file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    # 분석 실행
    with st.spinner("🔍 로그 분석 중... 잠시만 기다려주세요."):
        try:
            start_time = time.time()

            # 진행 상황 표시
            progress_bar = st.progress(0)
            status_text = st.empty()

            # 분석
            analyzer = st.session_state.analyzer
            df_result, results = analyzer.analyze_csv(
                temp_file_path,
                top_k=5,
                sample_size=sample_size
            )

            progress_bar.progress(100)

            # 요약 생성
            summary = analyzer.generate_summary(df_result, results)

            elapsed_time = time.time() - start_time

            # 결과 저장
            output_filename = f"{timestamp}_{uploaded_file.name.replace('.csv', '')}_analyzed.csv"
            output_path = os.path.join(OUTPUT_DIR, output_filename)
            df_result.to_csv(output_path, index=False)

            # 세션 상태 저장
            st.session_state.analysis_result = {
                'df': df_result,
                'summary': summary,
                'elapsed_time': elapsed_time,
                'output_path': output_path
            }

            status_text.success(f"✅ 분석 완료! (소요 시간: {elapsed_time:.2f}초)")
            progress_bar.empty()

        except Exception as e:
            st.error(f"❌ 분석 중 오류 발생: {e}")
            import traceback
            st.code(traceback.format_exc())


# 분석 결과 표시
if st.session_state.analysis_result is not None:
    result = st.session_state.analysis_result
    summary = result['summary']
    df = result['df']

    st.markdown("---")
    st.header("📊 분석 결과")

    # 주요 지표
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "총 로그 수",
            f"{summary['total_logs']:,}개"
        )

    with col2:
        st.metric(
            "악성 로그",
            f"{summary['malware_detected']:,}개",
            delta=f"{summary['malware_percentage']:.1f}%"
        )

    with col3:
        st.metric(
            "정상 로그",
            f"{summary['benign_detected']:,}개",
            delta=f"{100 - summary['malware_percentage']:.1f}%"
        )

    with col4:
        st.metric(
            "평균 확신도",
            f"{summary['average_confidence']:.1%}"
        )

    st.markdown("---")

    # 차트 표시
    tab1, tab2, tab3, tab4 = st.tabs(["📊 개요", "📈 공격 분석", "📋 상세 데이터", "💾 다운로드"])

    with tab1:
        col1, col2 = st.columns(2)

        with col1:
            st.plotly_chart(create_pie_chart(summary), use_container_width=True)

        with col2:
            st.plotly_chart(create_confidence_histogram(df), use_container_width=True)

    with tab2:
        col1, col2 = st.columns(2)

        with col1:
            st.plotly_chart(create_attack_distribution_chart(summary), use_container_width=True)

        with col2:
            st.plotly_chart(create_attack_confidence_chart(summary), use_container_width=True)

        # 공격 유형별 상세 정보
        st.subheader("공격 유형별 상세 정보")

        attack_details = []
        for attack_type, stats in summary['attack_stats'].items():
            attack_details.append({
                '공격 유형': attack_type,
                '탐지 횟수': stats['count'],
                '비율 (%)': f"{stats['percentage']:.1f}",
                '평균 확신도 (%)': f"{stats['avg_confidence'] * 100:.1f}"
            })

        st.dataframe(
            pd.DataFrame(attack_details).sort_values('탐지 횟수', ascending=False),
            width='stretch',
            hide_index=True
        )

    with tab3:
        st.subheader("분석 결과 전체 데이터")

        # 필터링 옵션
        col1, col2 = st.columns(2)

        with col1:
            filter_malware = st.selectbox(
                "악성 여부 필터",
                ["전체", "악성만", "정상만"]
            )

        with col2:
            attack_types = ["전체"] + list(summary['attack_type_distribution'].keys())
            filter_attack = st.selectbox("공격 유형 필터", attack_types)

        # 필터 적용
        filtered_df = df.copy()

        if filter_malware == "악성만":
            filtered_df = filtered_df[filtered_df['is_malware'] == True]
        elif filter_malware == "정상만":
            filtered_df = filtered_df[filtered_df['is_malware'] == False]

        if filter_attack != "전체":
            filtered_df = filtered_df[filtered_df['detected_attack_type'] == filter_attack]

        st.write(f"필터링된 결과: {len(filtered_df):,}개")

        # 데이터 표시
        display_cols = ['is_malware', 'detected_attack_type', 'confidence', 'similarity_score']
        st.dataframe(
            filtered_df[display_cols].head(100),
            width='stretch'
        )

        if len(filtered_df) > 100:
            st.info(f"상위 100개만 표시됩니다. 전체 데이터는 다운로드 탭에서 받을 수 있습니다.")

    with tab4:
        st.subheader("분석 결과 다운로드")

        col1, col2 = st.columns(2)

        with col1:
            st.download_button(
                label="📥 전체 결과 다운로드 (CSV)",
                data=df.to_csv(index=False).encode('utf-8'),
                file_name=f"analysis_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime='text/csv',
                width='stretch'
            )

        with col2:
            # 요약 리포트
            report_text = f"""# 분석 리포트

## 개요
- 분석 일시: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- 총 로그 수: {summary['total_logs']:,}개
- 악성 로그: {summary['malware_detected']:,}개 ({summary['malware_percentage']:.1f}%)
- 정상 로그: {summary['benign_detected']:,}개 ({100 - summary['malware_percentage']:.1f}%)
- 평균 확신도: {summary['average_confidence']:.2%}
- 분석 소요 시간: {result['elapsed_time']:.2f}초

## 공격 유형별 분포
"""
            for attack_type, count in sorted(summary['attack_type_distribution'].items(),
                                             key=lambda x: x[1], reverse=True):
                percentage = count / summary['total_logs'] * 100
                report_text += f"- {attack_type}: {count:,}개 ({percentage:.1f}%)\n"

            st.download_button(
                label="📥 요약 리포트 다운로드 (TXT)",
                data=report_text.encode('utf-8'),
                file_name=f"summary_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime='text/plain',
                width='stretch'
            )

        st.info(f"💾 분석 결과는 자동으로 저장되었습니다: `{result['output_path']}`")


# ========== 챗봇 기능 ==========

def generate_context_from_result(result):
    """분석 결과로부터 컨텍스트 생성"""
    if result is None:
        return "현재 분석된 데이터가 없습니다."

    summary = result['summary']
    df = result['df']

    context = f"""
현재 분석된 데이터 요약:
- 총 로그 수: {summary['total_logs']:,}개
- 악성 로그: {summary['malware_detected']:,}개 ({summary['malware_percentage']:.1f}%)
- 정상 로그: {summary['benign_detected']:,}개
- 평균 확신도: {summary['average_confidence']:.2%}

공격 유형별 분포:
"""
    for attack_type, stats in summary['attack_stats'].items():
        context += f"- {attack_type}: {stats['count']}개 ({stats['percentage']:.1f}%), 평균 확신도: {stats['avg_confidence']:.2%}\n"

    return context


def chat_with_ai(user_message, context, api_key):
    """OpenAI API를 사용하여 챗봇 응답 생성"""
    try:
        client = OpenAI(api_key=api_key)

        system_prompt = f"""당신은 사이버 보안 및 랜섬웨어 분석 전문가 AI 어시스턴트입니다.
사용자의 네트워크 로그 분석 결과를 바탕으로 질문에 답변해주세요.

현재 분석 데이터 컨텍스트:
{context}

답변 시 주의사항:
- 전문적이면서도 이해하기 쉽게 설명하세요
- 구체적인 수치와 데이터를 활용하세요
- 보안 권장사항을 제시하세요
- 한국어로 답변하세요
"""

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                *[{"role": msg["role"], "content": msg["content"]}
                  for msg in st.session_state.chat_history[-10:]],  # 최근 10개 대화만 포함
                {"role": "user", "content": user_message}
            ],
            temperature=0.7,
            max_tokens=800
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"❌ 오류 발생: {str(e)}\n\nAPI 키를 확인하거나 사이드바에서 설정해주세요."


# 플로팅 챗봇 UI
if st.session_state.analysis_result is not None:
    # 플로팅 CSS
    float_init()

    # 챗봇 토글 버튼 (우측 하단 고정)
    button_css = float_css_helper(
        position="fixed",
        bottom="20px",
        right="20px",
        z_index="999",
        transition="all 0.3s ease"
    )

    # 컨테이너를 사용하여 버튼 배치
    button_container = st.container()

    with button_container:
        st.markdown(
            f"""
            <style>
            {button_css}
            .stButton > button {{
                width: 60px;
                height: 60px;
                border-radius: 50%;
                font-size: 24px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border: none;
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
                cursor: pointer;
                transition: transform 0.3s ease;
            }}
            .stButton > button:hover {{
                transform: scale(1.1);
            }}
            </style>
            """,
            unsafe_allow_html=True
        )

        if st.button("💬", key="chatbot_toggle"):
            st.session_state.show_chatbot = not st.session_state.show_chatbot

    # 챗봇 창
    if st.session_state.show_chatbot:
        # 챗봇 창 CSS
        chat_css = """
        <style>
        .chat-container {
            position: fixed;
            bottom: 100px;
            right: 20px;
            width: 400px;
            height: 600px;
            background: white;
            border-radius: 15px;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
            z-index: 998;
            display: flex;
            flex-direction: column;
        }
        .chat-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            border-radius: 15px 15px 0 0;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 15px;
            background: #f8f9fa;
        }
        .message-user {
            background: #667eea;
            color: white;
            padding: 10px 15px;
            border-radius: 18px 18px 0 18px;
            margin: 5px 0;
            margin-left: auto;
            max-width: 80%;
            word-wrap: break-word;
        }
        .message-ai {
            background: white;
            color: #333;
            padding: 10px 15px;
            border-radius: 18px 18px 18px 0;
            margin: 5px 0;
            max-width: 80%;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            word-wrap: break-word;
        }
        </style>
        """
        st.markdown(chat_css, unsafe_allow_html=True)

        # 채팅 컨테이너
        with st.container():
            st.markdown("### 🤖 AI 보안 어시스턴트")
            st.markdown("분석 결과에 대해 질문해보세요!")

            # 채팅 히스토리 표시
            chat_container = st.container()
            with chat_container:
                for msg in st.session_state.chat_history:
                    if msg["role"] == "user":
                        st.markdown(f"**🧑 사용자:** {msg['content']}")
                    else:
                        st.markdown(f"**🤖 AI:** {msg['content']}")

            # 입력창
            st.markdown("---")

            # 예시 질문 버튼
            st.markdown("**💡 예시 질문:**")
            col1, col2 = st.columns(2)

            with col1:
                if st.button("🔍 가장 위험한 공격은?", key="q1"):
                    question = "가장 위험한 공격 유형은 무엇이고, 몇 개나 탐지되었나요?"
                    # 직접 처리
                    if not st.session_state.openai_api_key:
                        st.session_state.openai_api_key = os.getenv('OPENAI_API_KEY', '')

                    if st.session_state.openai_api_key:
                        st.session_state.chat_history.append({"role": "user", "content": question})
                        context = generate_context_from_result(st.session_state.analysis_result)
                        with st.spinner("AI가 답변을 생성 중..."):
                            ai_response = chat_with_ai(question, context, st.session_state.openai_api_key)
                        st.session_state.chat_history.append({"role": "assistant", "content": ai_response})
                    st.rerun()

                if st.button("📊 전체 요약해줘", key="q2"):
                    question = "전체 분석 결과를 요약해줘"
                    if not st.session_state.openai_api_key:
                        st.session_state.openai_api_key = os.getenv('OPENAI_API_KEY', '')

                    if st.session_state.openai_api_key:
                        st.session_state.chat_history.append({"role": "user", "content": question})
                        context = generate_context_from_result(st.session_state.analysis_result)
                        with st.spinner("AI가 답변을 생성 중..."):
                            ai_response = chat_with_ai(question, context, st.session_state.openai_api_key)
                        st.session_state.chat_history.append({"role": "assistant", "content": ai_response})
                    st.rerun()

            with col2:
                if st.button("⚠️ 조치사항은?", key="q3"):
                    question = "이 분석 결과를 보고 어떤 조치를 취해야 하나요?"
                    if not st.session_state.openai_api_key:
                        st.session_state.openai_api_key = os.getenv('OPENAI_API_KEY', '')

                    if st.session_state.openai_api_key:
                        st.session_state.chat_history.append({"role": "user", "content": question})
                        context = generate_context_from_result(st.session_state.analysis_result)
                        with st.spinner("AI가 답변을 생성 중..."):
                            ai_response = chat_with_ai(question, context, st.session_state.openai_api_key)
                        st.session_state.chat_history.append({"role": "assistant", "content": ai_response})
                    st.rerun()

                if st.button("🔒 보안 강화 방법은?", key="q4"):
                    question = "보안을 강화하려면 어떻게 해야 하나요?"
                    if not st.session_state.openai_api_key:
                        st.session_state.openai_api_key = os.getenv('OPENAI_API_KEY', '')

                    if st.session_state.openai_api_key:
                        st.session_state.chat_history.append({"role": "user", "content": question})
                        context = generate_context_from_result(st.session_state.analysis_result)
                        with st.spinner("AI가 답변을 생성 중..."):
                            ai_response = chat_with_ai(question, context, st.session_state.openai_api_key)
                        st.session_state.chat_history.append({"role": "assistant", "content": ai_response})
                    st.rerun()

            st.markdown("---")

            # 사용자 입력
            with st.form(key="chat_form", clear_on_submit=True):
                user_input = st.text_input(
                    "메시지를 입력하세요...",
                    key="user_message",
                    label_visibility="collapsed"
                )

                col1, col2 = st.columns([4, 1])
                with col1:
                    send_button = st.form_submit_button("전송", use_container_width=True)
                with col2:
                    clear_button = st.form_submit_button("초기화")

            # 전송 버튼 클릭 시
            if send_button and user_input:
                # .env에서 API 키 다시 확인
                if not st.session_state.openai_api_key:
                    st.session_state.openai_api_key = os.getenv('OPENAI_API_KEY', '')

                if not st.session_state.openai_api_key:
                    st.error("❌ OpenAI API 키를 찾을 수 없습니다. .env 파일에 OPENAI_API_KEY를 설정해주세요.")
                else:
                    # 사용자 메시지 추가
                    st.session_state.chat_history.append({
                        "role": "user",
                        "content": user_input
                    })

                    # 컨텍스트 생성
                    context = generate_context_from_result(st.session_state.analysis_result)

                    # AI 응답 생성
                    with st.spinner("AI가 답변을 생성 중..."):
                        ai_response = chat_with_ai(
                            user_input,
                            context,
                            st.session_state.openai_api_key
                        )

                    # AI 응답 추가
                    st.session_state.chat_history.append({
                        "role": "assistant",
                        "content": ai_response
                    })

                    # 페이지 새로고침
                    st.rerun()

            # 초기화 버튼
            if clear_button:
                st.session_state.chat_history = []
                st.rerun()


# 푸터
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: gray; padding: 20px;'>
        🛡️ AI 기반 랜섬웨어 탐지 시스템 v2.0<br>
        벡터 DB 기반 유사도 분석 | LangChain + FAISS + OpenAI
    </div>
    """,
    unsafe_allow_html=True
)
