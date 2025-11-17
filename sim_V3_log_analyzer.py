"""
로그 분석 엔진 v2
새로운 CSV 로그 파일을 분석하여 랜섬웨어 및 악성코드 탐지
벡터 유사도 기반 분류 (LLM 없이 무료로 작동)
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

        if not silent:
            print("🔧 로그 분석 엔진 초기화 중...")

        # 1. 임베딩 모델 로드
        if not silent:
            print("  - 임베딩 모델 로드...")
        self.embeddings = HuggingFaceEmbeddings(
            model_name='sentence-transformers/all-MiniLM-L6-v2',
            model_kwargs={'device': 'cpu'}
        )

        # 2. 벡터 DB 로드
        if not silent:
            print("  - 벡터 DB 로드...")
        self.vectordb = FAISS.load_local(
            self.db_path,
            self.embeddings,
            allow_dangerous_deserialization=True
        )
        if not silent:
            print(f"  ✅ {self.vectordb.index.ntotal}개 벡터 로드 완료")
            print("✅ 로그 분석 엔진 초기화 완료!\n")

    def preprocess_csv(self, csv_path: str) -> pd.DataFrame:
        """
        CSV 파일 전처리

        Args:
            csv_path: CSV 파일 경로

        Returns:
            전처리된 DataFrame
        """
        print(f"📂 CSV 파일 로드 중: {os.path.basename(csv_path)}")

        # CSV 읽기
        df = pd.read_csv(csv_path)
        print(f"  - 총 {len(df):,}개 행 로드")
        print(f"  - 컬럼: {len(df.columns)}개")

        # 결측치 처리
        df = df.fillna(0)

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
        # 숫자형 값만 선택 (문자열 값은 제외)
        parts = []
        for col, val in row.items():
            # 숫자형 데이터만 포함
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
        # 벡터 DB에서 유사한 문서 검색
        docs = self.vectordb.similarity_search_with_score(row_text, k=top_k)

        # 결과 분석
        attack_types = []
        labels = []
        scores = []

        for doc, score in docs:
            metadata = doc.metadata
            attack_types.append(metadata.get('attack_cat', 'Unknown'))
            labels.append(metadata.get('label', 'Unknown'))
            scores.append(float(score))

        # 가장 유사한 문서의 정보 사용
        best_doc, best_score = docs[0]

        # 공격 유형 중 가장 많이 나온 것 선택 (투표 방식)
        from collections import Counter
        attack_counter = Counter(attack_types)
        most_common_attack = attack_counter.most_common(1)[0][0] if attack_types else "Unknown"

        # 라벨 판단 (악성/정상)
        label_counter = Counter(labels)
        most_common_label = label_counter.most_common(1)[0][0] if labels else "Unknown"

        # 확신도 계산 (거리를 확신도로 변환)
        # 거리가 작을수록 확신도가 높음
        confidence = 1 / (1 + best_score) if best_score > 0 else 1.0

        return {
            'is_malware': most_common_label == '악성',
            'attack_type': most_common_attack,
            'confidence': confidence,
            'similarity_score': best_score,
            'top_matches': attack_types[:3],  # 상위 3개만 저장
            'match_scores': scores[:3]
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
        # 1. CSV 전처리
        df = self.preprocess_csv(csv_path)

        # 샘플링 (테스트용)
        if sample_size and sample_size < len(df):
            print(f"  ⚠️  테스트를 위해 {sample_size}개 행만 샘플링합니다.\n")
            df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)

        # 2. 각 행 분석
        print(f"🔍 {len(df):,}개 로그 분석 중...")

        results = []
        for idx, row in df.iterrows():
            # 진행 상황 표시
            if (idx + 1) % 100 == 0 or idx == 0:
                print(f"  진행: {idx + 1}/{len(df)} ({(idx + 1) / len(df) * 100:.1f}%)")

            # 행을 텍스트로 변환
            row_text = self.row_to_text(row)

            # 분석 수행
            result = self.analyze_single_row(row_text, top_k=top_k)
            results.append(result)

        print(f"  ✅ 분석 완료!\n")

        # 3. 결과를 DataFrame에 추가
        df['is_malware'] = [r['is_malware'] for r in results]
        df['detected_attack_type'] = [r['attack_type'] for r in results]
        df['confidence'] = [r['confidence'] for r in results]
        df['similarity_score'] = [r['similarity_score'] for r in results]

        return df, results

    def generate_summary(self, df: pd.DataFrame, results: List[Dict]) -> Dict:
        """
        분석 결과 요약 생성

        Args:
            df: 분석 결과 DataFrame
            results: 분석 결과 리스트

        Returns:
            요약 통계 딕셔너리
        """
        total_rows = len(df)
        malware_count = df['is_malware'].sum()
        benign_count = total_rows - malware_count

        # 공격 유형별 카운트
        attack_type_counts = df['detected_attack_type'].value_counts().to_dict()

        # 평균 확신도
        avg_confidence = df['confidence'].mean()

        # 공격 유형별 통계
        attack_stats = {}
        for attack_type in attack_type_counts.keys():
            attack_df = df[df['detected_attack_type'] == attack_type]
            attack_stats[attack_type] = {
                'count': len(attack_df),
                'avg_confidence': attack_df['confidence'].mean(),
                'percentage': len(attack_df) / total_rows * 100
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


def print_summary(summary: Dict):
    """요약 결과 출력"""
    print("=" * 80)
    print("📊 분석 결과 요약")
    print("=" * 80)
    print(f"\n총 로그 수: {summary['total_logs']:,}개")
    print(f"악성코드 탐지: {summary['malware_detected']:,}개 ({summary['malware_percentage']:.1f}%)")
    print(f"정상 로그: {summary['benign_detected']:,}개 ({100 - summary['malware_percentage']:.1f}%)")
    print(f"평균 확신도: {summary['average_confidence']:.2%}")

    print("\n" + "=" * 80)
    print("공격 유형별 상세 분석")
    print("=" * 80)

    for attack_type, stats in sorted(summary['attack_stats'].items(),
                                     key=lambda x: x[1]['count'], reverse=True):
        print(f"\n[{attack_type}]")
        print(f"  - 탐지 횟수: {stats['count']:,}개 ({stats['percentage']:.1f}%)")
        print(f"  - 평균 확신도: {stats['avg_confidence']:.2%}")

    print("\n" + "=" * 80)


def main():
    """메인 실행 함수"""
    print("=" * 80)
    print("🛡️  로그 분석 엔진 v2 - 랜섬웨어 탐지 시스템")
    print("=" * 80)
    print()

    # 분석 엔진 초기화
    try:
        analyzer = LogAnalyzer()
    except Exception as e:
        print(f"❌ 로그 분석 엔진 초기화 실패: {e}")
        return

    # 테스트용 CSV 파일 경로 입력
    print("분석할 CSV 파일 경로를 입력하세요:")
    print("(또는 Enter를 눌러 샘플 파일 자동 선택)")
    csv_path = input("CSV 경로: ").strip()

    # 기본 샘플 파일 사용
    if not csv_path:
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # 가능한 샘플 파일들 찾기
        sample_candidates = [
            os.path.join(script_dir, "dataset", "Ransomware", "Ransomware_1.csv"),
            os.path.join(script_dir, "dataset", "Ransomware", "Ransomware_2.csv"),
            os.path.join(script_dir, "dataset", "UNSW-NB15", "UNSW-NB15_1.csv"),
            os.path.join(script_dir, "dataset", "Adware", "Adware_1.csv"),
        ]

        for sample_file in sample_candidates:
            if os.path.exists(sample_file):
                csv_path = sample_file
                print(f"  → 샘플 파일 선택: {os.path.basename(csv_path)}")
                break

        if not csv_path:
            print("❌ 샘플 파일을 찾을 수 없습니다.")
            print("dataset/ 폴더에 CSV 파일이 있는지 확인하세요.")
            return

    if not os.path.exists(csv_path):
        print(f"❌ 파일을 찾을 수 없습니다: {csv_path}")
        return

    # 샘플 크기 설정
    print("\n분석할 로그 개수를 입력하세요 (Enter = 전체 분석):")
    sample_input = input("개수: ").strip()
    sample_size = int(sample_input) if sample_input.isdigit() else None

    print()

    # 분석 실행
    try:
        import time
        start_time = time.time()

        df_result, results = analyzer.analyze_csv(csv_path, top_k=5, sample_size=sample_size)

        # 요약 생성
        summary = analyzer.generate_summary(df_result, results)

        # 결과 출력
        print_summary(summary)

        # 실행 시간
        elapsed_time = time.time() - start_time
        print(f"\n⏱️  분석 소요 시간: {elapsed_time:.2f}초")

        # 상세 결과 샘플 출력
        print("\n" + "=" * 80)
        print("📋 상세 결과 샘플 (처음 10개)")
        print("=" * 80)
        display_cols = ['is_malware', 'detected_attack_type', 'confidence', 'similarity_score']
        available_cols = [col for col in display_cols if col in df_result.columns]
        print(df_result[available_cols].head(10).to_string(index=False))

        # 결과 저장
        output_path = csv_path.replace('.csv', '_analyzed.csv')
        df_result.to_csv(output_path, index=False)
        print(f"\n💾 분석 결과 저장: {output_path}")

    except Exception as e:
        print(f"\n❌ 분석 중 오류 발생: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
