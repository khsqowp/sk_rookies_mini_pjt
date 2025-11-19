# vector_db_integration.py
"""
Faiss 벡터 DB를 활용한 유사 랜섬웨어 샘플 검색 시스템
"""
import json
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
import faiss

from config import FEATURES_PATH, MODEL_PATH


class FaissRansomwareSearcher:
    """Faiss 기반 랜섬웨어 유사도 검색"""
    
    def __init__(
        self,
        index_path: Optional[Path] = None,
        use_gpu: bool = False
    ):
        """
        초기화
        
        Args:
            index_path: Faiss 인덱스 저장 경로 (None이면 자동 생성)
            use_gpu: GPU 사용 여부
        """
        self.use_gpu = use_gpu and faiss.get_num_gpus() > 0
        
        # 피처 로딩
        self.features = json.loads(FEATURES_PATH.read_text(encoding="utf-8"))
        self.vector_size = len(self.features)
        
        # Faiss 인덱스 초기화
        self.index = None
        self.metadata = []  # 메타데이터 저장
        
        # 인덱스 경로 설정
        if index_path is None:
            index_path = MODEL_PATH.parent / "faiss_index"
        self.index_path = Path(index_path)
        self.index_path.mkdir(parents=True, exist_ok=True)
        
        print(f"✅ Faiss VectorDB 초기화 완료")
        print(f"   - 벡터 차원: {self.vector_size}")
        print(f"   - 피처 수: {len(self.features)}")
        print(f"   - GPU 사용: {self.use_gpu}")
        print(f"   - 인덱스 경로: {self.index_path}")
    
    def create_index(self, use_ivf: bool = True, nlist: int = 100):
        """
        Faiss 인덱스 생성
        
        Args:
            use_ivf: IVF (Inverted File) 인덱스 사용 여부 (대용량 데이터에 적합)
            nlist: IVF의 클러스터 수
        """
        try:
            if use_ivf and nlist > 0:
                # IVF + L2 거리 (빠른 검색)
                quantizer = faiss.IndexFlatL2(self.vector_size)
                self.index = faiss.IndexIVFFlat(quantizer, self.vector_size, nlist)
                print(f"✅ IVF 인덱스 생성 완료 (nlist={nlist})")
            else:
                # Flat L2 인덱스 (정확하지만 느림)
                self.index = faiss.IndexFlatL2(self.vector_size)
                print(f"✅ Flat L2 인덱스 생성 완료")
            
            # GPU로 이동
            if self.use_gpu:
                res = faiss.StandardGpuResources()
                self.index = faiss.index_cpu_to_gpu(res, 0, self.index)
                print(f"✅ GPU로 인덱스 이동 완료")
                
        except Exception as e:
            print(f"⚠️  인덱스 생성 실패: {e}")
            # Fallback to flat index
            self.index = faiss.IndexFlatL2(self.vector_size)
    
    def _header_to_vector(self, header_features: Dict[str, float]) -> np.ndarray:
        """
        헤더 피처를 벡터로 변환 (정규화)
        
        Args:
            header_features: 헤더 피처 딕셔너리
        
        Returns:
            정규화된 피처 벡터
        """
        # 선택된 피처만 추출
        values = np.array([
            float(header_features.get(f, 0)) 
            for f in self.features
        ], dtype=np.float32)
        
        # 정규화 (바이트 값 0-255를 0-1로)
        values = values / 255.0
        
        # L2 정규화 (코사인 유사도용)
        norm = np.linalg.norm(values)
        if norm > 1e-10:
            values = values / norm
        
        return values
    
    def insert_samples(self, csv_path: Path):
        """
        CSV 데이터셋을 Faiss 인덱스에 삽입
        
        Args:
            csv_path: 데이터셋 CSV 경로
        """
        print(f"\n[+] 데이터 삽입 시작: {csv_path}")
        
        df = pd.read_csv(csv_path)
        byte_cols = sorted([c for c in df.columns if c.isdigit()], key=lambda x: int(x))
        
        vectors = []
        self.metadata = []
        
        for idx, row in df.iterrows():
            # 헤더 피처 추출
            header_features = {
                col: float(row[col]) 
                for col in byte_cols 
                if col in self.features
            }
            
            # 벡터 변환
            vector = self._header_to_vector(header_features)
            vectors.append(vector)
            
            # 메타데이터 저장
            self.metadata.append({
                "idx": idx,
                "id": int(row.get("ID", idx)),
                "filename": str(row.get("filename", f"sample_{idx}")),
                "family": str(row.get("family", "unknown")),
                "label": int(row["GR"]),  # 0=정상, 1=랜섬웨어
                "label_text": "ransomware" if row["GR"] == 1 else "benign"
            })
            
            if (idx + 1) % 1000 == 0:
                print(f"    진행: {idx+1}/{len(df)} 샘플")
        
        # NumPy 배열로 변환
        vectors = np.array(vectors, dtype=np.float32)
        
        # IVF 인덱스인 경우 학습 필요
        if isinstance(self.index, faiss.IndexIVFFlat):
            print("    IVF 인덱스 학습 중...")
            self.index.train(vectors)
            print("    ✅ 학습 완료")
        
        # 벡터 추가
        self.index.add(vectors)
        
        print(f"✅ 총 {len(df)}개 샘플 삽입 완료")
        print(f"   인덱스 크기: {self.index.ntotal}")
    
    def save_index(self):
        """Faiss 인덱스 및 메타데이터 저장"""
        # GPU 인덱스는 CPU로 변환 후 저장
        if self.use_gpu:
            index_to_save = faiss.index_gpu_to_cpu(self.index)
        else:
            index_to_save = self.index
        
        # 인덱스 저장
        index_file = self.index_path / "faiss.index"
        faiss.write_index(index_to_save, str(index_file))
        print(f"✅ Faiss 인덱스 저장: {index_file}")
        
        # 메타데이터 저장
        metadata_file = self.index_path / "metadata.pkl"
        with open(metadata_file, 'wb') as f:
            pickle.dump(self.metadata, f)
        print(f"✅ 메타데이터 저장: {metadata_file}")
    
    def load_index(self):
        """Faiss 인덱스 및 메타데이터 로딩"""
        index_file = self.index_path / "faiss.index"
        metadata_file = self.index_path / "metadata.pkl"
        
        if not index_file.exists():
            print(f"⚠️  인덱스 파일이 없습니다: {index_file}")
            return False
        
        # 인덱스 로딩
        self.index = faiss.read_index(str(index_file))
        
        # GPU로 이동
        if self.use_gpu:
            res = faiss.StandardGpuResources()
            self.index = faiss.index_cpu_to_gpu(res, 0, self.index)
        
        print(f"✅ Faiss 인덱스 로딩: {index_file}")
        
        # 메타데이터 로딩
        if metadata_file.exists():
            with open(metadata_file, 'rb') as f:
                self.metadata = pickle.load(f)
            print(f"✅ 메타데이터 로딩: {metadata_file}")
        
        print(f"   인덱스 크기: {self.index.ntotal}")
        return True
    
    def search_similar(
        self,
        query_features: Dict[str, float],
        top_k: int = 10,
        label_filter: Optional[int] = None
    ) -> List[Dict]:
        """
        유사한 샘플 검색
        
        Args:
            query_features: 검색할 헤더 피처
            top_k: 반환할 결과 수
            label_filter: 0(정상) 또는 1(랜섬웨어)로 필터링 (None이면 전체)
        
        Returns:
            유사 샘플 리스트
        """
        if self.index is None or self.index.ntotal == 0:
            print("⚠️  인덱스가 비어있습니다.")
            return []
        
        # 쿼리 벡터 생성
        query_vector = self._header_to_vector(query_features)
        query_vector = query_vector.reshape(1, -1).astype(np.float32)
        
        # 검색 (더 많이 검색 후 필터링)
        search_k = top_k * 10 if label_filter is not None else top_k
        search_k = min(search_k, self.index.ntotal)
        
        distances, indices = self.index.search(query_vector, search_k)
        
        # 결과 포맷팅
        similar_samples = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx == -1:  # 유효하지 않은 인덱스
                continue
            
            meta = self.metadata[idx]
            
            # 라벨 필터링
            if label_filter is not None and meta['label'] != label_filter:
                continue
            
            # 거리를 유사도로 변환 (L2 거리 -> 코사인 유사도)
            # 정규화된 벡터의 경우: similarity = 1 - (distance^2 / 2)
            similarity = max(0, 1 - (dist / 2))
            
            similar_samples.append({
                "idx": int(idx),
                "id": meta["id"],
                "score": float(similarity),
                "distance": float(dist),
                "filename": meta["filename"],
                "family": meta["family"],
                "label": meta["label"],
                "label_text": meta["label_text"]
            })
            
            if len(similar_samples) >= top_k:
                break
        
        return similar_samples
    
    def analyze_with_similar_samples(
        self,
        query_features: Dict[str, float],
        query_filename: str = "unknown.exe",
        top_k: int = 5
    ) -> Dict:
        """
        유사 샘플 기반 분석
        
        Args:
            query_features: 분석할 헤더 피처
            query_filename: 파일명
            top_k: 검색할 유사 샘플 수
        
        Returns:
            분석 결과 딕셔너리
        """
        # 전체 유사 샘플 검색
        all_similar = self.search_similar(query_features, top_k=top_k * 2)
        
        # 랜섬웨어 유사 샘플
        ransomware_similar = self.search_similar(
            query_features, 
            top_k=top_k,
            label_filter=1
        )
        
        # 정상 유사 샘플
        benign_similar = self.search_similar(
            query_features,
            top_k=top_k,
            label_filter=0
        )
        
        # 유사도 점수 기반 판정
        if ransomware_similar and benign_similar:
            avg_ransom_score = np.mean([s['score'] for s in ransomware_similar])
            avg_benign_score = np.mean([s['score'] for s in benign_similar])
            
            # 랜섬웨어 유사도가 더 높으면 위험
            risk_level = "high" if avg_ransom_score > avg_benign_score else "low"
        elif ransomware_similar:
            risk_level = "high"
        else:
            risk_level = "low"
        
        return {
            "query_filename": query_filename,
            "risk_level": risk_level,
            "all_similar": all_similar[:top_k],
            "ransomware_similar": ransomware_similar,
            "benign_similar": benign_similar,
            "avg_ransomware_similarity": np.mean([s['score'] for s in ransomware_similar]) if ransomware_similar else 0,
            "avg_benign_similarity": np.mean([s['score'] for s in benign_similar]) if benign_similar else 0
        }
    
    def print_analysis_report(self, analysis_result: Dict):
        """분석 결과 리포트 출력"""
        print("\n" + "=" * 80)
        print("벡터 DB 기반 유사 샘플 분석 리포트")
        print("=" * 80)
        print(f"\n파일명: {analysis_result['query_filename']}")
        print(f"위험도: {analysis_result['risk_level'].upper()}")
        print(f"랜섬웨어 평균 유사도: {analysis_result['avg_ransomware_similarity']:.4f}")
        print(f"정상 파일 평균 유사도: {analysis_result['avg_benign_similarity']:.4f}")
        
        print("\n--- 가장 유사한 랜섬웨어 샘플 ---")
        for i, sample in enumerate(analysis_result['ransomware_similar'], 1):
            print(f"[{i}] {sample['filename']} ({sample['family']})")
            print(f"    유사도: {sample['score']:.4f}")
        
        print("\n--- 가장 유사한 정상 샘플 ---")
        for i, sample in enumerate(analysis_result['benign_similar'], 1):
            print(f"[{i}] {sample['filename']}")
            print(f"    유사도: {sample['score']:.4f}")
        
        print("=" * 80)


# ==================== 메인 실행 ====================
def main():
    """Faiss 벡터 DB 통합 시스템 메인"""
    
    CSV_PATH = Path(
        r"C:\Users\sec\OneDrive\바탕 화면\SK쉴더스\ransom_dectection_model\sk_rookies_mini_pjt\Ransomware_headers.csv"
    )
    
    # Faiss 검색기 초기화
    searcher = FaissRansomwareSearcher(use_gpu=False)
    
    # 기존 인덱스 로딩 시도
    if searcher.load_index():
        print("\n✅ 기존 인덱스를 사용합니다.")
    else:
        # 1. 인덱스 생성
        print("\n[1] Faiss 인덱스 생성")
        searcher.create_index(use_ivf=True, nlist=100)
        
        # 2. 데이터 삽입
        print("\n[2] 데이터셋 Faiss 인덱스에 삽입")
        searcher.insert_samples(csv_path=CSV_PATH)
        
        # 3. 인덱스 저장
        print("\n[3] 인덱스 저장")
        searcher.save_index()
    
    # 4. 샘플 검색 테스트
    print("\n[4] 샘플 검색 테스트")
    df = pd.read_csv(CSV_PATH)
    
    # 랜섬웨어 샘플 하나 선택
    ransomware_sample = df[df['GR'] == 1].iloc[0]
    byte_cols = sorted([c for c in df.columns if c.isdigit()], key=lambda x: int(x))
    
    sample_features = {
        col: float(ransomware_sample[col]) 
        for col in byte_cols 
        if col in searcher.features
    }
    
    # 유사 샘플 분석
    analysis = searcher.analyze_with_similar_samples(
        query_features=sample_features,
        query_filename=ransomware_sample.get('filename', 'test_ransomware.exe'),
        top_k=5
    )
    
    # 리포트 출력
    searcher.print_analysis_report(analysis)
    
    # 5. 성능 벤치마크
    print("\n[5] 검색 성능 벤치마크")
    import time
    
    # 정상 샘플로 테스트
    benign_sample = df[df['GR'] == 0].iloc[0]
    benign_features = {
        col: float(benign_sample[col]) 
        for col in byte_cols 
        if col in searcher.features
    }
    
    start = time.time()
    for _ in range(100):
        searcher.search_similar(benign_features, top_k=10)
    elapsed = time.time() - start
    
    print(f"   100회 검색 시간: {elapsed:.3f}초")
    print(f"   평균 검색 시간: {elapsed/100*1000:.2f}ms")
    
    print("\n✅ Faiss 벡터 DB 통합 시스템 구축 완료!")


if __name__ == "__main__":
    main()