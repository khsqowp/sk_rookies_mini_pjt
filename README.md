# 🛡️ AI 기반 랜섬웨어 탐지 시스템

벡터 DB 기반 유사도 분석과 LLM을 활용한 네트워크 로그 분석 및 악성코드 탐지 시스템입니다.

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.51.0-red)
![LangChain](https://img.shields.io/badge/LangChain-0.3-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 📋 목차
- [주요 기능](#주요-기능)
- [시스템 아키텍처](#시스템-아키텍처)
- [설치 방법](#설치-방법)
- [사용 방법](#사용-방법)
- [프로젝트 구조](#프로젝트-구조)
- [기술 스택](#기술-스택)

---

## ✨ 주요 기능

### 1. 📊 로그 분석 엔진
- **벡터 기반 유사도 검색**: 50만 개의 악성코드 샘플로 학습된 벡터 DB
- **실시간 악성코드 탐지**: CSV 로그 파일 업로드 시 실시간 분석
- **다양한 공격 유형 분류**: Ransomware, Adware, Backdoor, DoS 등
- **확신도 점수 제공**: 각 탐지 결과에 대한 신뢰도 측정

### 2. 🎨 인터랙티브 대시보드
- **실시간 시각화**: Plotly 기반 인터랙티브 차트
- **다양한 차트 제공**:
  - 파이 차트: 악성/정상 비율
  - 막대 그래프: 공격 유형별 분포
  - 히스토그램: 확신도 분포
  - 테이블: 상세 분석 결과

### 3. 💬 AI 챗봇 (플로팅 UI)
- **우측 하단 플로팅 버튼**: 클릭 시 채팅창 표시/숨김
- **컨텍스트 기반 답변**: 현재 분석 결과를 바탕으로 질문 답변
- **예시 질문 제공**: 빠른 인사이트 확인
- **OpenAI GPT 연동**: 전문적이고 상세한 보안 분석

### 4. 💾 데이터 관리
- **분석 결과 저장**: CSV 형식으로 자동 저장
- **요약 리포트 생성**: TXT 형식의 분석 보고서
- **이전 분석 불러오기**: 과거 분석 결과 재확인

---

## 🏗️ 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────┐
│                     사용자                               │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│              Streamlit Dashboard                        │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ 파일 업로드  │  │ 시각화 차트   │  │ AI 챗봇       │  │
│  └─────────────┘  └──────────────┘  └───────────────┘  │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│             Log Analyzer (로그 분석 엔진)                │
│  ┌──────────────────────────────────────────────────┐   │
│  │ 1. CSV 전처리                                     │   │
│  │ 2. 행(row) → 벡터 변환                            │   │
│  │ 3. 벡터 DB 유사도 검색 (Top-5)                    │   │
│  │ 4. 투표 방식 공격 유형 분류                        │   │
│  │ 5. 확신도 점수 계산                                │   │
│  └──────────────────────────────────────────────────┘   │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│              FAISS Vector DB (500,000 vectors)          │
│  ┌──────────────────────────────────────────────────┐   │
│  │ • UNSW-NB15 (네트워크 침입 탐지)                  │   │
│  │ • CIC-AndMal2017 (안드로이드 악성코드)            │   │
│  │   - Ransomware (101 files)                       │   │
│  │   - Adware (104 files)                           │   │
│  │   - Scareware (112 files)                        │   │
│  │   - SMSmalware (109 files)                       │   │
│  │   - Benign (1700 files)                          │   │
│  └──────────────────────────────────────────────────┘   │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│        Sentence Transformers (임베딩 모델)              │
│           all-MiniLM-L6-v2 (로컬, 무료)                 │
└─────────────────────────────────────────────────────────┘
```

---

## 🚀 설치 방법

### 1. 저장소 클론
```bash
git clone <repository-url>
cd Mini_PJT2
```

### 2. 가상환경 생성 및 활성화
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### 3. 의존성 패키지 설치
```bash
pip install -r requirements.txt
```

### 4. 환경변수 설정
```bash
cp .env.example .env
# .env 파일을 열어 OpenAI API 키 입력
```

### 5. 벡터 DB 생성 (최초 1회)
```bash
python vector_db_builder.py
```
⏱️ **소요 시간**: 약 30-60분 (데이터셋 크기에 따라 다름)

---

## 📖 사용 방법

### 1. 대시보드 실행
```bash
streamlit run dashboard_v2.py
```

브라우저가 자동으로 열리며 `http://localhost:8501`에서 접속됩니다.

### 2. 로그 파일 분석
1. **CSV 파일 업로드**: 네트워크 로그 CSV 파일 선택
2. **샘플링 설정** (선택사항): 빠른 테스트를 위해 샘플 크기 조정
3. **분석 시작 버튼 클릭**
4. **결과 확인**: 차트와 테이블로 분석 결과 확인

### 3. AI 챗봇 사용
1. **분석 완료 후** 우측 하단 💬 버튼 클릭
2. 예시 질문 버튼 클릭 또는 직접 질문 입력
3. AI가 현재 분석 결과를 바탕으로 답변 제공

### 4. 결과 다운로드
- **다운로드 탭**에서 CSV 또는 TXT 형식으로 저장
- `output_analysis/` 폴더에 자동 저장

---

## 📁 프로젝트 구조

```
Mini_PJT2/
├── dashboard_v2.py              # 메인 대시보드 (Streamlit)
├── log_analyzer_v2.py           # 로그 분석 엔진
├── vector_db_builder.py         # 벡터 DB 생성 스크립트
├── test_vector_search.py        # 벡터 검색 테스트
├── requirements.txt             # 의존성 패키지 목록
├── .env.example                 # 환경변수 예시
├── .gitignore                   # Git 제외 파일 목록
├── README.md                    # 프로젝트 문서
│
├── dataset/                     # 데이터셋 폴더
│   ├── UNSW-NB15/              # 네트워크 침입 탐지 데이터
│   ├── Ransomware/             # 랜섬웨어 샘플
│   ├── Adware/                 # 애드웨어 샘플
│   ├── Scareware/              # 스케어웨어 샘플
│   ├── SMSmalware/             # SMS 악성코드 샘플
│   └── Benign/                 # 정상 트래픽 샘플
│
├── vector_db/                   # 벡터 DB 저장소
│   └── faiss_index/
│       ├── index.faiss         # FAISS 인덱스 (732MB)
│       └── index.pkl           # 메타데이터 (405MB)
│
├── uploads/                     # 업로드된 파일
├── output_analysis/             # 분석 결과
└── .venv/                       # 가상환경 (제외)
```

---

## 🛠️ 기술 스택

### 백엔드
- **Python 3.13**
- **LangChain**: RAG 시스템 구축
- **FAISS**: 벡터 유사도 검색
- **Sentence Transformers**: 텍스트 임베딩
- **OpenAI API**: GPT-4o-mini 챗봇

### 프론트엔드
- **Streamlit**: 웹 대시보드 프레임워크
- **Plotly**: 인터랙티브 차트
- **Streamlit-Float**: 플로팅 UI 컴포넌트

### 데이터 처리
- **Pandas**: 데이터 분석 및 전처리
- **NumPy**: 수치 연산

---

## 📊 데이터셋

### UNSW-NB15
- **출처**: University of New South Wales
- **설명**: 네트워크 침입 탐지 데이터셋
- **공격 유형**: Normal, Generic, Exploits, DoS, Reconnaissance, Backdoor 등

### CIC-AndMal2017
- **출처**: Canadian Institute for Cybersecurity
- **설명**: 안드로이드 악성코드 네트워크 트래픽
- **포함**: Ransomware, Adware, Scareware, SMSmalware, Benign

---

## 🔧 주요 설정

### 샘플링 설정
- **기본값**: 1,000개 행
- **권장**: 빠른 테스트용 (1-5분 소요)
- **전체 분석**: 샘플링 해제 (시간 오래 걸림)

### 벡터 검색 파라미터
- **Top-K**: 5 (유사한 문서 5개 검색)
- **임베딩 모델**: all-MiniLM-L6-v2
- **확신도 계산**: `1 / (1 + distance)`

---

## 🤝 기여

이슈 제출 및 풀 리퀘스트를 환영합니다!

---

## 📝 라이선스

MIT License

---

## 👨‍💻 개발자

**Mini_PJT2 팀**

---

## 📞 문의

프로젝트 관련 문의사항이 있으시면 Issues를 통해 연락주세요.

---

## 🙏 감사의 말

- **UNSW-NB15 Dataset**: University of New South Wales
- **CIC-AndMal2017 Dataset**: Canadian Institute for Cybersecurity
- **HuggingFace**: Sentence Transformers 모델 제공
- **OpenAI**: GPT API 제공

---

**🛡️ 안전한 네트워크 환경을 만들어갑니다!**
