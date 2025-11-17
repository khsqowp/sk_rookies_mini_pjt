"""
로그 분석 엔진 v4
- v2와 sim_v3의 기능을 통합한 표준 분석 엔진
- 벡터 유사도 기반 악성코드 탐지
"""
import os
import pandas as pd
import numpy as np
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from typing import Dict, List
import warnings
warnings.filterwarnings('ignore')


class LogAnalyzer:
    def __init__(self, vector_db_path: str = None, silent: bool = False):
        """
        로그 분석 엔진 초기화

        Args:
            vector_db_path: 벡터 DB 경로 (기본값: ./vector_db/faiss_index)
            silent: True일 경우 초기화 메시지를 출력하지 않음
        """
        # 경로 설정
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if vector_db_path is None:
            vector_db_path = os.path.join(script_dir, "vector_db", "faiss_index")

        self.db_path = vector_db_path
        self.silent = silent

        if not self.silent:
            print("🔧 로그 분석 엔진(V4) 초기화 중...")

        # 1. 임베딩 모델 로드
        if not self.silent:
            print("  - 임베딩 모델 로드...")
        self.embeddings = HuggingFaceEmbeddings(
            model_name='sentence-transformers/all-MiniLM-L6-v2',
            model_kwargs={'device': 'cpu'}
        )

        # 2. 벡터 DB 로드
        if not self.silent:
            print("  - 벡터 DB 로드...")
        
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"벡터 DB 파일을 찾을 수 없습니다: {self.db_path}. 'vector_db_builder.py'를 먼저 실행해주세요.")

        self.vectordb = FAISS.load_local(
            self.db_path,
            self.embeddings,
            allow_dangerous_deserialization=True
        )
        if not self.silent:
            print(f"  ✅ {self.vectordb.index.ntotal}개 벡터 로드 완료")
            print("✅ 로그 분석 엔진(V4) 초기화 완료!\n")

    def preprocess_csv(self, csv_path: str) -> pd.DataFrame:
        """
        CSV 파일 전처리

        Args:
            csv_path: CSV 파일 경로

        Returns:
            전처리된 DataFrame
        """
        if not self.silent:
            print(f"📂 CSV 파일 로드 중: {os.path.basename(csv_path)}")

        df = pd.read_csv(csv_path)
        
        if not self.silent:
            print(f"  - 총 {len(df):,}개 행 로드")
            print(f"  - 컬럼: {len(df.columns)}개")

        # 결측치 처리
        df = df.fillna(0)

        if not self.silent:
            print(f"  ✅ 전처리 완료")
        return df

    def row_to_text(self, row: pd.Series) -> str:
        """
        DataFrame의 한 행을 텍스트로 변환

        Args:
            row: DataFrame의 한 행

        Returns:
            텍스트 형식의 행 데이터
        """
        parts = []
        for col, val in row.items():
            if isinstance(val, (int, float, np.integer, np.floating)) and not pd.isna(val):
                parts.append(f"{col}: {val}")

        return ", ".join(parts)

    def analyze_single_row(self, row_text: str, top_k: int = 5) -> Dict:
        """
        단일 로그 행 분석

        Args:
            row_text: 텍스트로 변환된 로그 행
            top_k: 검색할 유사 문서 개수

        Returns:
            분석 결과 딕셔너리
        """
        docs = self.vectordb.similarity_search_with_score(row_text, k=top_k)

        attack_types = []
        labels = []
        scores = []

        for doc, score in docs:
            metadata = doc.metadata
            attack_types.append(metadata.get('attack_cat', 'Unknown'))
            labels.append(metadata.get('label', 'Unknown'))
            scores.append(float(score))

        best_doc, best_score = docs[0]

        from collections import Counter
        attack_counter = Counter(attack_types)
        most_common_attack = attack_counter.most_common(1)[0][0] if attack_types else "Unknown"

        label_counter = Counter(labels)
        most_common_label = label_counter.most_common(1)[0][0] if labels else "Unknown"

        confidence = 1 / (1 + best_score) if best_score > 0 else 1.0

        # 소스 IP와 목적지 IP 추출 (컬럼 이름이 존재할 경우)
        src_ip, dst_ip = "N/A", "N/A"
        try:
            parts = row_text.split(", ")
            for part in parts:
                if "Source IP:" in part:
                    src_ip = part.split(":")[1].strip()
                if "Destination IP:" in part:
                    dst_ip = part.split(":")[1].strip()
        except Exception:
            pass # IP 정보가 없는 경우 무시

        return {
            'is_malware': most_common_label == '악성',
            'attack_type': most_common_attack,
            'confidence': confidence,
            'similarity_score': best_score,
            'top_matches': attack_types[:3],
            'match_scores': scores[:3],
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'log_text': row_text,
        }

    def analyze_csv(self, csv_path: str, top_k: int = 5, sample_size: int = None) -> tuple:
        """
        전체 CSV 파일 분석

        Args:
            csv_path: CSV 파일 경로
            top_k: 각 행마다 검색할 유사 문서 개수
            sample_size: 샘플링할 행 개수 (None이면 전체)

        Returns:
            (분석 결과 DataFrame, 분석 결과 리스트) 튜플
        """
        df = self.preprocess_csv(csv_path)

        if sample_size and sample_size < len(df):
            if not self.silent:
                print(f"  ⚠️  테스트를 위해 {sample_size}개 행만 샘플링합니다.\n")
            df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)

        if not self.silent:
            print(f"🔍 {len(df):,}개 로그 분석 중...")

        results = []
        for idx, row in df.iterrows():
            if not self.silent and (idx + 1) % 100 == 0 or idx == 0:
                print(f"  진행: {idx + 1}/{len(df)} ({(idx + 1) / len(df) * 100:.1f}%)")

            row_text = self.row_to_text(row)
            result = self.analyze_single_row(row_text, top_k=top_k)
            results.append(result)

        if not self.silent:
            print(f"  ✅ 분석 완료!\n")

        df_results = pd.DataFrame(results)
        
        # 원본 데이터프레임과 결과 데이터프레임 병합
        # 인덱스를 기준으로 합치므로, 샘플링을 했더라도 인덱스가 맞아야 함
        df.reset_index(drop=True, inplace=True)
        df_results.reset_index(drop=True, inplace=True)
        
        final_df = pd.concat([df, df_results], axis=1)

        return final_df, results

    def generate_summary(self, df: pd.DataFrame) -> Dict:
        """
        분석 결과 요약 생성

        Args:
            df: 분석 결과 DataFrame

        Returns:
            요약 통계 딕셔너리
        """
        total_rows = len(df)
        malware_count = df['is_malware'].sum()
        benign_count = total_rows - malware_count

        attack_type_counts = df['attack_type'].value_counts().to_dict()
        avg_confidence = df['confidence'].mean()

        attack_stats = {}
        for attack_type, count in attack_type_counts.items():
            attack_df = df[df['attack_type'] == attack_type]
            attack_stats[attack_type] = {
                'count': count,
                'avg_confidence': attack_df['confidence'].mean(),
                'percentage': count / total_rows * 100 if total_rows > 0 else 0
            }

        summary = {
            'total_logs': total_rows,
            'malware_detected': int(malware_count),
            'benign_detected': int(benign_count),
            'malware_percentage': (malware_count / total_rows * 100) if total_rows > 0 else 0,
            'attack_type_distribution': attack_type_counts,
            'attack_stats': attack_stats,
            'average_confidence': avg_confidence
        }

        return summary
