import os
from dotenv import load_dotenv
import pandas as pd
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_core.prompts import ChatPromptTemplate

# .env 파일에서 환경 변수 로드
load_dotenv()

# --- 1. 상수 정의 ---
script_dir = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(script_dir, "vector_db")
DB_FAISS_PATH = os.path.join(DB_DIR, "faiss_index")

# UNSW-NB15 데이터셋 피처
UNSW_FEATURES = [
    'proto', 'service', 'state', 'sbytes', 'dbytes', 'sttl', 'dttl',
    'sload', 'dload', 'spkts', 'dpkts', 'smean', 'dmean',
    'ct_state_ttl', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm',
    'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'attack_cat', 'label'
]

# CIC-AndMal2017 데이터셋 피처
CIC_FEATURES = [
    'Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Fwd IAT Mean', 'Bwd IAT Mean',
    'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'Label'
]

# 집계에 사용할 피처 (label 제외)
UNSW_AGGREGATION = [f for f in UNSW_FEATURES if f not in ['attack_cat', 'label']]
CIC_AGGREGATION = [f for f in CIC_FEATURES if f != 'Label']

# 하위 호환성을 위한 별칭
SELECTED_FEATURES = UNSW_FEATURES
FEATURES_FOR_AGGREGATION = UNSW_AGGREGATION

# --- 2. LLM 및 임베딩 모델 초기화 ---
# 실제 실행 시점에서 API 키가 유효해야 함
llm = ChatOpenAI(model="gpt-4", temperature=0.7)
embeddings = OpenAIEmbeddings()

# --- 3. 프롬프트 템플릿 정의 ---
ANALYZER_PROMPT_TEMPLATE = """
당신은 네트워크 보안 위협 분석에 특화된 AI 보안 전문가입니다.

아래에 제공된 두 가지 정보를 바탕으로 악성 공격 패턴(특히 랜섬웨어)을 보이는지 판별하고, 그 근거를 상세히 설명해주세요.

1.  **과거 유사 공격 패턴**:
    {retrieved_docs}

2.  **업로드된 파일의 집계된 특징 데이터**:
    {new_data}

**분석 지시**:
위 '과거 유사 공격 패턴'과 '업로드된 파일의 집계된 특징 데이터'를 면밀히 비교 분석하여 다음 질문에 답해주세요.

**알려진 공격 유형**:
- **Ransomware**: 랜섬웨어 (파일 암호화, 높은 데이터 전송률)
- **Adware**: 애드웨어 (광고 표시, 정보 수집)
- **Scareware**: 스케어웨어 (가짜 경고)
- **SMSmalware**: SMS 악성코드
- **Backdoor**: 백도어 (원격 접근)
- **DoS**: 서비스 거부 공격
- **Exploits**: 취약점 공격
- **Generic**: 일반 악성 행위
- **Benign**: 정상 트래픽

**분석 결과**:
- **악성 여부**: [악성 의심 / 정상] 중 하나로 명확히 판별해주세요.
- **공격 유형**: 악성으로 판단될 경우, 위 목록 중 가장 가능성이 높은 공격 유형을 명시해주세요.
- **판단 근거**: 과거 유사 공격 패턴과 업로드된 파일의 집계된 특징 데이터를 비교하여 구체적인 피처(feature) 값을 근거로 설명해주세요.
- **랜섬웨어 특징**: 랜섬웨어로 의심될 경우, 다음 특징 중 해당하는 것을 명시해주세요:
  * 높은 데이터 전송량 (암호화된 파일 전송)
  * 빠른 전송 속도 (대량 파일 처리)
  * 특정 포트 집중 사용 (SMB, RDP 등)
  * 측면 이동 패턴 (네트워크 확산)
"""

analyzer_prompt = ChatPromptTemplate.from_template(ANALYZER_PROMPT_TEMPLATE)

# --- 4. 핵심 분석 함수 (스캐폴드) ---

def _create_document_from_series(series: pd.Series, features_to_use: list) -> Document:
    """
    Pandas Series (데이터 한 행)를 LangChain Document 객체로 변환합니다.
    지정된 피처들을 텍스트로 조합하여 page_content를 생성합니다.
    """
    content = []
    for feature_name in features_to_use:
        if feature_name in series and pd.notna(series[feature_name]):
            content.append(f"{feature_name}: {series[feature_name]}")
    
    page_content = ", ".join(content)
    
    # 메타데이터는 분석 대상 신규 데이터에는 필요 없으므로 비워둡니다.
    metadata = {}
    
    return Document(page_content=page_content, metadata=metadata)

def detect_dataset_type(df: pd.DataFrame) -> str:
    """
    DataFrame의 컬럼을 보고 어떤 데이터셋 형식인지 자동 감지
    """
    columns = set(df.columns.str.strip())

    if 'proto' in columns and 'sbytes' in columns and 'ct_state_ttl' in columns:
        return 'UNSW'
    elif 'Flow Duration' in columns and 'Total Fwd Packets' in columns:
        return 'CIC'
    else:
        return 'UNKNOWN'

def analyze_ransomware_pattern(uploaded_file_path: str) -> dict:
    """
    업로드된 파일을 분석하여 랜섬웨어 패턴 여부를 판별합니다.
    (현재는 스캐폴드이며, 벡터 DB가 준비되어야 완전한 기능을 수행합니다.)

    Args:
        uploaded_file_path (str): 사용자가 업로드한 파일의 경로.

    Returns:
        dict: 분석 결과 (랜섬웨어 여부, 근거, 공격 유형 등).
    """
    print("--- 로그 분석 시작 ---")
    
    # 1. 벡터 DB 로드
    if not os.path.exists(DB_FAISS_PATH):
        return {
            "error": "벡터 DB 파일을 찾을 수 없습니다. 'vector_db_builder.py'를 먼저 실행해야 합니다."
        }
    try:
        print("벡터 DB 로드 중...")
        db = FAISS.load_local(DB_FAISS_PATH, embeddings, allow_dangerous_deserialization=True)
        print("벡터 DB 로드 완료.")
    except Exception as e:
        return {"error": f"벡터 DB 로드 중 오류 발생: {e}"}

    # 2. 업로드된 파일 데이터 처리
    try:
        print(f"업로드된 파일 '{uploaded_file_path}' 처리 중...")
        df_new = pd.read_csv(uploaded_file_path)
        df_new.columns = df_new.columns.str.strip()

        # 데이터셋 타입 자동 감지
        dataset_type = detect_dataset_type(df_new)
        print(f"데이터셋 타입: {dataset_type}")

        # 데이터셋 타입에 따른 피처 선택
        if dataset_type == 'UNSW':
            aggregation_features = UNSW_AGGREGATION
            label_col = 'label'
        elif dataset_type == 'CIC':
            aggregation_features = CIC_AGGREGATION
            label_col = 'Label'
        else:
            # 알 수 없는 형식은 숫자형 컬럼만 사용
            aggregation_features = df_new.select_dtypes(include=['number']).columns.tolist()
            label_col = None

        # 공격 행만 필터링 (label 컬럼이 있는 경우)
        if label_col and label_col in df_new.columns:
            if dataset_type == 'CIC':
                # CIC 데이터는 Label이 문자열 (예: "RANSOMWARE_SIMPLOCKER")
                df_attacks = df_new[~df_new[label_col].str.upper().str.contains('BENIGN', na=False)]
            else:
                # UNSW 데이터는 label이 0/1
                df_attacks = df_new[df_new[label_col] == 1]

            if not df_attacks.empty:
                print("공격 행이 감지되었습니다. 공격 행만 집계하여 분석합니다.")
                df_to_aggregate = df_attacks
            else:
                print("공격 행이 감지되지 않았습니다. 전체 파일을 집계하여 분석합니다.")
                df_to_aggregate = df_new
        else:
            df_to_aggregate = df_new

        # 분석에 필요한 피처만 선택
        df_processed = df_to_aggregate[[f for f in aggregation_features if f in df_to_aggregate.columns]]

        # 숫자형 피처와 범주형 피처 분리
        numeric_features = df_processed.select_dtypes(include=['number']).columns
        categorical_features = df_processed.select_dtypes(include=['object']).columns

        # 집계 통계 계산
        aggregated_data = {}
        for col in numeric_features:
            aggregated_data[f"{col}_mean"] = df_processed[col].mean()
            aggregated_data[f"{col}_max"] = df_processed[col].max()
            aggregated_data[f"{col}_min"] = df_processed[col].min()
            aggregated_data[f"{col}_std"] = df_processed[col].std() # 표준편차 추가
        
        for col in categorical_features:
            # 최빈값이 여러 개일 경우 첫 번째 값만 사용
            aggregated_data[f"{col}_mode"] = df_processed[col].mode()[0] if not df_processed[col].mode().empty else 'N/A'

        # 집계된 데이터를 Pandas Series로 변환하여 Document 생성
        aggregated_series = pd.Series(aggregated_data)
        new_data_document = _create_document_from_series(aggregated_series, aggregation_features)
        new_data_text = new_data_document.page_content

        print("업로드된 파일 데이터 처리 완료.")

    except Exception as e:
        return {"error": f"업로드된 파일 처리 중 오류 발생: {e}"}

    # 3. 유사도 검색
    try:
        print("유사도 검색 수행 중...")
        # 업로드된 파일의 집계된 데이터를 기반으로 가장 유사한 패턴 검색
        retrieved_docs = db.similarity_search(new_data_document.page_content, k=3)
        retrieved_docs_text = "\n\n".join([doc.page_content for doc in retrieved_docs])
        print(f"{len(retrieved_docs)}개의 유사 패턴을 찾았습니다.")
    except Exception as e:
        return {"error": f"유사도 검색 중 오류 발생: {e}"}

    # 4. LLM을 통한 분석 및 판별
    try:
        print("LLM 분석 요청 중...")
        chain = analyzer_prompt | llm
        response = chain.invoke({
            "retrieved_docs": retrieved_docs_text,
            "new_data": new_data_text
        })
        
        analysis_result = response.content
        print("LLM 분석 완료.")

        # 공격 유형 및 탐지 결과 파싱
        detected_attack_type = "Unknown"
        is_malicious = False

        # 악성 여부 판단
        malicious_keywords = ["악성 의심", "공격", "위협", "랜섬웨어", "애드웨어", "멀웨어"]
        is_malicious = any(keyword in analysis_result for keyword in malicious_keywords)

        # 특정 공격 유형 추출
        attack_types = {
            "Ransomware": ["랜섬웨어", "Ransomware", "암호화"],
            "Adware": ["애드웨어", "Adware", "광고"],
            "Scareware": ["스케어웨어", "Scareware", "가짜 경고"],
            "SMSmalware": ["SMS", "문자"],
            "Backdoor": ["백도어", "Backdoor", "원격 접근"],
            "DoS": ["DoS", "DDoS", "서비스 거부"],
            "Exploits": ["Exploits", "취약점"],
            "Generic": ["Generic", "일반 악성"]
        }

        for attack_name, keywords in attack_types.items():
            if any(keyword in analysis_result for keyword in keywords):
                detected_attack_type = attack_name
                break

        # 유사도 검색 결과에서도 공격 유형 추출
        if detected_attack_type == "Unknown" and retrieved_docs:
            for doc in retrieved_docs:
                if doc.metadata.get("label") == 1:
                    detected_attack_type = doc.metadata.get("attack_cat", "Generic")
                    break

        # 정상일 경우
        if not is_malicious or "정상" in analysis_result:
            detected_attack_type = "Benign"
            is_malicious = False

        return {
            "is_ransomware": detected_attack_type == "Ransomware",
            "is_malicious": is_malicious,
            "attack_cat": detected_attack_type,
            "report": analysis_result,
            "error": None
        }

    except Exception as e:
        # API 키 오류 등이 여기서 발생할 가능성이 높음
        return {"error": f"LLM 분석 중 오류 발생: {e}"}

if __name__ == '__main__':
    # 직접 실행 시 테스트 (테스트 파일이 필요함)
    print("log_analyzer.py는 직접 실행용이 아니며, dashboard.py를 통해 사용됩니다.")
    # 예시: result = analyze_ransomware_pattern("path/to/your/test_log.csv")
    # print(result)
