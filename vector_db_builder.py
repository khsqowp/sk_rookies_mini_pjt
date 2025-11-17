import os
import glob
import pandas as pd
from dotenv import load_dotenv
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
import time
import random
from tqdm import tqdm

# .env 파일에서 환경 변수 로드
load_dotenv()

# --- 1. 상수 정의 ---
# 스크립트의 현재 위치를 기준으로 경로 설정
script_dir = os.path.dirname(os.path.abspath(__file__))
# 데이터 파일들이 있는 디렉토리
DATA_DIR = os.path.join(script_dir, "CSV Files")
# 벡터 DB를 저장할 디렉토리
DB_DIR = os.path.join(script_dir, "vector_db")
DB_FAISS_PATH = os.path.join(DB_DIR, "faiss_index")

# DB 저장 디렉터리가 없으면 생성
os.makedirs(DB_DIR, exist_ok=True)

# --- 샘플링 및 배치 설정 ---
# 각 파일에서 샘플링할 최대 행 수 (None이면 전체 사용)
MAX_ROWS_PER_FILE = 1000  # 파일당 1000행으로 증가
# 임베딩 배치 크기 (한 번에 처리할 문서 수)
EMBEDDING_BATCH_SIZE = 500  # 배치 크기 감소로 안정성 향상
# 전체 문서 제한 (None이면 제한 없음)
MAX_TOTAL_DOCUMENTS = 500000  # 전체 50만 개로 대폭 증가

# --- 2. 전처리를 위한 피처 선택 ---
# UNSW-NB15 데이터셋 피처 (기존)
UNSW_FEATURES = [
    'proto', 'service', 'state', 'sbytes', 'dbytes', 'sttl', 'dttl',
    'sload', 'dload', 'spkts', 'dpkts', 'smean', 'dmean',
    'ct_state_ttl', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm',
    'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'attack_cat', 'label'
]

# CIC-AndMal2017 데이터셋 피처 (Ransomware, Adware 등)
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

def detect_dataset_type(df: pd.DataFrame) -> str:
    """
    DataFrame의 컬럼을 보고 어떤 데이터셋 형식인지 자동 감지
    """
    columns = set(df.columns.str.strip())

    # UNSW-NB15 특징적 컬럼 확인
    if 'proto' in columns and 'sbytes' in columns and 'ct_state_ttl' in columns:
        return 'UNSW'
    # CIC-AndMal2017 특징적 컬럼 확인
    elif 'Flow Duration' in columns and 'Total Fwd Packets' in columns:
        return 'CIC'
    else:
        return 'UNKNOWN'

def extract_attack_category(label_value, file_path=''):
    """
    Label 값이나 파일 경로에서 공격 유형 추출
    """
    if pd.isna(label_value):
        # 파일 경로에서 추출 (예: .../Ransomware/Simplocker/...)
        if 'Ransomware' in file_path:
            return 'Ransomware'
        elif 'Adware' in file_path:
            return 'Adware'
        elif 'Scareware' in file_path:
            return 'Scareware'
        elif 'SMSmalware' in file_path:
            return 'SMSmalware'
        elif 'Benign' in file_path:
            return 'Benign'
        else:
            return 'Unknown'

    # Label에서 추출 (예: "RANSOMWARE_SIMPLOCKER")
    label_str = str(label_value).upper()
    if 'RANSOMWARE' in label_str:
        return 'Ransomware'
    elif 'ADWARE' in label_str:
        return 'Adware'
    elif 'SCAREWARE' in label_str:
        return 'Scareware'
    elif 'SMS' in label_str:
        return 'SMSmalware'
    elif 'BENIGN' in label_str or label_value == 0:
        return 'Benign'
    else:
        return label_str

def create_documents_from_dataframe(df: pd.DataFrame, file_path='', max_rows=None) -> list[Document]:
    """
    Pandas DataFrame의 각 행을 LangChain Document 객체로 변환합니다.
    UNSW-NB15와 CIC-AndMal2017 형식을 자동 감지하여 처리합니다.

    Args:
        df: 처리할 DataFrame
        file_path: 파일 경로 (공격 유형 추출용)
        max_rows: 샘플링할 최대 행 수 (None이면 전체 사용)
    """
    documents = []

    # 데이터셋 타입 자동 감지
    dataset_type = detect_dataset_type(df)

    if dataset_type == 'UNSW':
        selected_features = UNSW_FEATURES
        df_features = df.drop(columns=['id'], errors='ignore')
    elif dataset_type == 'CIC':
        selected_features = CIC_FEATURES
        df_features = df.drop(columns=['Flow ID', 'Source IP', 'Destination IP', 'Timestamp'], errors='ignore')
    else:
        print(f"   [경고] 알 수 없는 데이터셋 형식입니다. 모든 컬럼을 사용합니다.")
        selected_features = df.columns.tolist()
        df_features = df

    # 샘플링 적용
    if max_rows and len(df_features) > max_rows:
        df_features = df_features.sample(n=max_rows, random_state=42)

    for _, row in df_features.iterrows():
        # 선택된 피처들을 기반으로 텍스트 콘텐츠 생성
        content = []
        for feature in selected_features:
            if feature in row and pd.notna(row[feature]):
                content.append(f"{feature}: {row[feature]}")

        page_content = ", ".join(content)

        # 메타데이터 생성 - 데이터셋 타입에 따라 다르게 처리
        if dataset_type == 'UNSW':
            metadata = {
                "attack_cat": row.get('attack_cat', 'Unknown'),
                "label": int(row.get('label', 0))
            }
        elif dataset_type == 'CIC':
            # CIC 데이터는 Label 컬럼에서 공격 유형 추출
            label_value = row.get('Label', 'Unknown')
            attack_cat = extract_attack_category(label_value, file_path)
            metadata = {
                "attack_cat": attack_cat,
                "label": 1 if attack_cat != 'Benign' else 0
            }
        else:
            metadata = {
                "attack_cat": "Unknown",
                "label": 0
            }

        doc = Document(page_content=page_content, metadata=metadata)
        documents.append(doc)

    return documents

def build_vector_db():
    """
    지정된 디렉터리에서 CSV 파일들을 재귀적으로 읽어 FAISS 벡터 데이터베이스를 구축하고 저장합니다.
    UNSW-NB15, Ransomware, Adware, Scareware, SMSmalware, Benign 데이터를 모두 처리합니다.
    """
    print(f"'{DATA_DIR}'에서 모든 CSV 파일들을 수집하여 벡터 DB를 구축합니다...")
    print(f"설정: 파일당 최대 {MAX_ROWS_PER_FILE}행, 전체 최대 {MAX_TOTAL_DOCUMENTS}문서, 배치 크기 {EMBEDDING_BATCH_SIZE}")

    # 모든 CSV 파일 재귀적으로 찾기
    csv_files = []

    # UNSW-NB15 데이터셋 (기존)
    train_set_path = os.path.join(DATA_DIR, "Training and Testing Sets", "UNSW_NB15_training-set.csv")
    test_set_path = os.path.join(DATA_DIR, "Training and Testing Sets", "UNSW_NB15_testing-set.csv")
    if os.path.exists(train_set_path):
        csv_files.append(train_set_path)
    if os.path.exists(test_set_path):
        csv_files.append(test_set_path)

    # 새로운 데이터셋 폴더들 (Ransomware, Adware, Scareware, SMSmalware, Benign)
    malware_dirs = ['Ransomware', 'Adware', 'Scareware', 'SMSmalware', 'Benign']
    for malware_dir in malware_dirs:
        malware_path = os.path.join(DATA_DIR, malware_dir)
        if os.path.exists(malware_path):
            # 해당 디렉토리 내 모든 CSV 파일 찾기
            pattern = os.path.join(malware_path, "**", "*.csv")
            found_files = glob.glob(pattern, recursive=True)
            csv_files.extend(found_files)
            print(f"  [{malware_dir}] {len(found_files)}개의 CSV 파일 발견")

    if not csv_files:
        print("처리할 CSV 파일을 찾을 수 없습니다. 경로를 확인해주세요.")
        return

    print(f"\n총 {len(csv_files)}개의 CSV 파일을 처리합니다.\n")

    all_documents = []
    processed_count = 0
    error_count = 0

    # tqdm을 사용한 진행률 표시
    for file_path in tqdm(csv_files, desc="CSV 파일 처리 중", unit="파일"):
        try:
            # 전체 문서 제한 체크
            if MAX_TOTAL_DOCUMENTS and len(all_documents) >= MAX_TOTAL_DOCUMENTS:
                print(f"\n최대 문서 수({MAX_TOTAL_DOCUMENTS})에 도달하여 처리를 중단합니다.")
                break

            file_name = os.path.basename(file_path)

            df = pd.read_csv(file_path)

            # DataFrame의 컬럼 이름에서 공백 제거 및 정규화
            df.columns = df.columns.str.strip()

            # 빈 DataFrame 건너뛰기
            if df.empty:
                continue

            # DataFrame을 Document 리스트로 변환 (샘플링 적용)
            docs = create_documents_from_dataframe(df, file_path, max_rows=MAX_ROWS_PER_FILE)

            # 전체 문서 제한 고려
            if MAX_TOTAL_DOCUMENTS:
                remaining = MAX_TOTAL_DOCUMENTS - len(all_documents)
                if remaining > 0:
                    docs = docs[:remaining]

            all_documents.extend(docs)
            processed_count += 1

        except Exception as e:
            error_count += 1
            tqdm.write(f"   [오류] {file_name}: {e}")

    if not all_documents:
        print("처리할 수 있는 문서가 없습니다. 벡터 DB를 구축할 수 없습니다.")
        return

    print(f"\n=== CSV 처리 완료 ===")
    print(f"성공: {processed_count}개 파일")
    print(f"실패: {error_count}개 파일")
    print(f"총 {len(all_documents)}개의 문서를 수집했습니다.")
    print("\n임베딩 및 벡터 DB 구축을 시작합니다...")

    try:
        # HuggingFace 로컬 임베딩 모델 초기화
        print("로컬 임베딩 모델을 로드하는 중... (최초 실행 시 다운로드 소요)")
        embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_kwargs={'device': 'cpu'},
            encode_kwargs={'normalize_embeddings': True}
        )
        print("모델 로드 완료!")

        # 배치별로 처리하여 벡터 DB 생성
        print(f"배치 크기: {EMBEDDING_BATCH_SIZE}, 총 배치 수: {(len(all_documents) + EMBEDDING_BATCH_SIZE - 1) // EMBEDDING_BATCH_SIZE}")

        db = None
        for i in tqdm(range(0, len(all_documents), EMBEDDING_BATCH_SIZE), desc="임베딩 생성 중", unit="배치"):
            batch_docs = all_documents[i:i + EMBEDDING_BATCH_SIZE]

            if db is None:
                # 첫 번째 배치로 DB 초기화
                db = FAISS.from_documents(batch_docs, embeddings)
            else:
                # 이후 배치는 기존 DB에 추가
                batch_db = FAISS.from_documents(batch_docs, embeddings)
                db.merge_from(batch_db)

            # 중간 저장 (매 10 배치마다)
            if (i // EMBEDDING_BATCH_SIZE + 1) % 10 == 0:
                db.save_local(DB_FAISS_PATH)
                tqdm.write(f"   중간 저장 완료 ({i + len(batch_docs)}개 문서)")

        # 최종 저장
        db.save_local(DB_FAISS_PATH)
        print(f"\n벡터 DB를 성공적으로 구축하고 '{DB_FAISS_PATH}'에 저장했습니다.")
        print(f"총 {db.index.ntotal}개의 벡터가 저장되었습니다.")

    except Exception as e:
        print(f"\n[오류] FAISS 벡터 스토어 생성 또는 저장 중 오류가 발생했습니다: {e}")

        # 부분적으로라도 저장
        if db is not None:
            try:
                db.save_local(DB_FAISS_PATH)
                print(f"부분 결과를 '{DB_FAISS_PATH}'에 저장했습니다.")
            except:
                pass

if __name__ == "__main__":
    start_time = time.time()
    build_vector_db()
    end_time = time.time()
    print(f"\n총 실행 시간: {end_time - start_time:.2f}초")
