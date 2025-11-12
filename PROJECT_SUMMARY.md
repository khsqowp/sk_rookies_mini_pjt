# 📋 프로젝트 공유 체크리스트

## ✅ 공유할 파일 목록

### 1. **핵심 Python 파일** ✅
- ✅ `dashboard_v2.py` - 메인 대시보드
- ✅ `log_analyzer_v2.py` - 로그 분석 엔진
- ✅ `vector_db_builder.py` - 벡터 DB 생성
- ✅ `test_vector_search.py` - 테스트 스크립트

### 2. **설정 및 문서 파일** ✅
- ✅ `requirements.txt` - 패키지 의존성
- ✅ `README.md` - 프로젝트 문서
- ✅ `.env.example` - 환경변수 예시
- ✅ `.gitignore` - Git 제외 파일

### 3. **데이터 파일** (선택사항)
- ⚠️ `dataset/` - 데이터셋 (용량이 크므로 선택적 공유)
- ⚠️ `vector_db/` - 벡터 DB (1.1GB, 재생성 가능)

---

## 🚫 공유하지 말아야 할 파일

### 절대 공유 금지
- ❌ `.env` - API 키 포함 (보안 위험!)
- ❌ `.venv/` - 가상환경 폴더
- ❌ `__pycache__/` - Python 캐시

### 선택적 제외
- `uploads/` - 업로드된 테스트 파일
- `output_analysis/` - 분석 결과 파일

---

## 📦 프로젝트 압축 방법

### 옵션 1: 벡터 DB 포함 (전체 공유)
```bash
cd /Users/user/Desktop/CODE/Python/
tar -czf Mini_PJT2_full.tar.gz \
  --exclude='.venv' \
  --exclude='.env' \
  --exclude='__pycache__' \
  --exclude='uploads/*.csv' \
  --exclude='output_analysis/*.csv' \
  Mini_PJT2/
```
📊 **예상 크기**: 약 1.2GB

### 옵션 2: 벡터 DB 제외 (코드만)
```bash
cd /Users/user/Desktop/CODE/Python/
tar -czf Mini_PJT2_code_only.tar.gz \
  --exclude='.venv' \
  --exclude='.env' \
  --exclude='__pycache__' \
  --exclude='vector_db' \
  --exclude='dataset' \
  --exclude='uploads/*.csv' \
  --exclude='output_analysis/*.csv' \
  Mini_PJT2/
```
📊 **예상 크기**: 약 100MB

### 옵션 3: GitHub 업로드 (권장)
```bash
cd /Users/user/Desktop/CODE/Python/Mini_PJT2

# Git 초기화 (아직 안했다면)
git init

# .gitignore가 자동으로 불필요한 파일 제외
git add .
git commit -m "Initial commit: AI-based Ransomware Detection System"

# GitHub 저장소에 푸시
git remote add origin <your-github-repo-url>
git push -u origin main
```

---

## 📤 공유 방법별 가이드

### 1. **GitHub (권장)** ⭐
**장점**: 버전 관리, 협업 용이, 포트폴리오
**단점**: 대용량 파일 제한 (100MB)

**절차**:
1. GitHub에서 새 저장소 생성
2. 위의 Git 명령어로 푸시
3. `.gitignore`가 자동으로 불필요한 파일 제외
4. README.md가 자동으로 표시됨

**주의**:
- `vector_db/` 폴더는 1GB 이상이므로 Git LFS 필요
- 또는 벡터 DB는 제외하고 README에 생성 방법 명시

### 2. **구글 드라이브**
**장점**: 대용량 파일 공유 가능
**단점**: 버전 관리 없음

**절차**:
1. 위의 압축 명령어로 `.tar.gz` 생성
2. 구글 드라이브에 업로드
3. 공유 링크 생성

### 3. **이메일**
**장점**: 간단
**단점**: 용량 제한 (보통 25MB)

**절차**:
1. 옵션 2 (코드만) 사용
2. 압축 파일 첨부

---

## 🎯 수신자를 위한 안내

### README.md에 다음 내용 포함됨:
1. ✅ 설치 방법
2. ✅ 실행 방법
3. ✅ 환경변수 설정 (.env.example 제공)
4. ✅ 벡터 DB 생성 방법
5. ✅ 사용법 및 예시

### 수신자가 해야 할 일:
1. 가상환경 생성: `python -m venv .venv`
2. 패키지 설치: `pip install -r requirements.txt`
3. `.env` 파일 생성 및 API 키 입력
4. (벡터 DB 없으면) `python vector_db_builder.py` 실행
5. `streamlit run dashboard_v2.py` 실행

---

## ⚠️ 보안 체크리스트

공유하기 전에 꼭 확인하세요:

- [ ] `.env` 파일이 제외되었는가?
- [ ] API 키가 코드에 하드코딩되어 있지 않은가?
- [ ] `.gitignore`가 제대로 설정되었는가?
- [ ] 개인정보가 포함된 로그 파일이 없는가?
- [ ] 테스트 데이터에 민감한 정보가 없는가?

---

## 🎁 보너스: 데모 영상/스크린샷

프로젝트 공유 시 함께 제공하면 좋음:
1. 📸 Dashboard 스크린샷
2. 📸 분석 결과 차트 캡처
3. 📸 챗봇 대화 예시
4. 🎥 (선택) 데모 영상

---

## 📊 프로젝트 통계

- **총 코드 라인**: ~800줄 (Python)
- **벡터 DB 크기**: 500,000개
- **지원 데이터셋**: 2종 (UNSW-NB15, CIC-AndMal2017)
- **공격 유형**: 8종 (Ransomware, Adware, DoS 등)
- **분석 속도**: 100개/4초 (약 25개/초)

---

## ✅ 완료!

위 체크리스트를 따라 프로젝트를 안전하게 공유하세요.

**추천 방법**: GitHub + README.md (벡터 DB는 재생성 방식)
