import os
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS

# 경로 설정
script_dir = os.path.dirname(os.path.abspath(__file__))
DB_FAISS_PATH = os.path.join(script_dir, "vector_db", "faiss_index")

print("벡터 DB 로드 중...")

# 임베딩 모델 초기화 (vector_db_builder.py와 동일한 모델 사용)
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    model_kwargs={'device': 'cpu'},
    encode_kwargs={'normalize_embeddings': True}
)

# FAISS 벡터 DB 로드
db = FAISS.load_local(
    DB_FAISS_PATH,
    embeddings,
    allow_dangerous_deserialization=True  # 로컬 신뢰 파일이므로 허용
)

print(f"벡터 DB 로드 완료! 총 {db.index.ntotal}개의 벡터가 저장되어 있습니다.\n")

# 테스트 쿼리 목록
test_queries = [
    "ransomware attack",
    "network intrusion detection",
    "malware behavior",
    "benign traffic pattern"
]

print("=" * 60)
print("검색 테스트 시작")
print("=" * 60)

for query in test_queries:
    print(f"\n질의: '{query}'")
    print("-" * 60)

    # 유사 문서 검색 (상위 3개)
    results = db.similarity_search(query, k=3)

    for i, doc in enumerate(results, 1):
        print(f"\n[결과 {i}]")
        # 문서 내용 (처음 200자만)
        content_preview = doc.page_content[:200] + "..." if len(doc.page_content) > 200 else doc.page_content
        print(f"내용: {content_preview}")
        # 메타데이터
        print(f"공격 유형: {doc.metadata.get('attack_cat', 'Unknown')}")
        print(f"라벨: {'악성' if doc.metadata.get('label', 0) == 1 else '정상'}")

print("\n" + "=" * 60)
print("검색 테스트 완료!")
print("=" * 60)
