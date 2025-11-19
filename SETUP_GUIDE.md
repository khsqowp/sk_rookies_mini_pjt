# 🚀 프로젝트 설정 가이드 (Setup Guide)

다른 환경에서 이 프로젝트를 실행하기 위한 간단한 설정 가이드입니다.

---

## 📋 필수 사항 (Prerequisites)

- Python 3.8 이상
- pip (Python 패키지 관리자)
- Git (선택사항)

---

## 🔧 설정 단계 (Setup Steps)

### 1️⃣ 프로젝트 복사

프로젝트 폴더를 원하는 위치에 복사합니다.

```bash
# 예시: 바탕화면에 복사
cp -r Mini_PJT2 ~/Desktop/
cd ~/Desktop/Mini_PJT2
```

---

### 2️⃣ 가상환경 생성 및 활성화 (권장)

```bash
# 가상환경 생성
python -m venv .venv

# 가상환경 활성화
# Mac/Linux:
source .venv/bin/activate

# Windows:
.venv\Scripts\activate
```

---

### 3️⃣ 필요한 패키지 설치

```bash
pip install -r requirements.txt
```

---

### 4️⃣ 환경 변수 설정 (.env 파일)

#### 방법 1: .env.example 파일 복사 (권장)

```bash
# .env.example을 .env로 복사
cp .env.example .env
```

그 다음 `.env` 파일을 텍스트 에디터로 열어서 경로를 수정합니다:

```bash
# Mac/Linux
nano .env

# 또는
code .env  # VS Code 사용시
```

#### 방법 2: 직접 .env 파일 생성

`.env` 파일을 새로 만들고 아래 내용을 복사하여 붙여넣기:

```env
# API 키
OPENAI_API_KEY=your-openai-api-key-here

# 경로 설정 (자신의 환경에 맞게 수정!)
PROJECT_ROOT=/절대/경로/Mini_PJT2
MODEL_PATH=/절대/경로/Mini_PJT2/best_model_pe.keras
TEST_FILES_DIR=/절대/경로/Mini_PJT2/test_files
```

---

### 5️⃣ 경로 수정 방법

`.env` 파일에서 **반드시 수정해야 할 부분**:

#### 🖥️ Windows 사용자

```env
PROJECT_ROOT=C:/Users/YourName/Desktop/Mini_PJT2
MODEL_PATH=C:/Users/YourName/Desktop/Mini_PJT2/best_model_pe.keras
TEST_FILES_DIR=C:/Users/YourName/Desktop/Mini_PJT2/test_files
```

**주의**: Windows에서는 백슬래시(`\`) 대신 **슬래시(`/`)** 를 사용하세요!

#### 🍎 Mac 사용자

```env
PROJECT_ROOT=/Users/YourName/Desktop/Mini_PJT2
MODEL_PATH=/Users/YourName/Desktop/Mini_PJT2/best_model_pe.keras
TEST_FILES_DIR=/Users/YourName/Desktop/Mini_PJT2/test_files
```

#### 🐧 Linux 사용자

```env
PROJECT_ROOT=/home/username/projects/Mini_PJT2
MODEL_PATH=/home/username/projects/Mini_PJT2/best_model_pe.keras
TEST_FILES_DIR=/home/username/projects/Mini_PJT2/test_files
```

---

### 6️⃣ OpenAI API 키 설정 (AI 보고서 사용 시)

AI 보고서 생성 기능을 사용하려면 OpenAI API 키가 필요합니다:

1. [OpenAI Platform](https://platform.openai.com/api-keys)에 접속
2. API 키 생성
3. `.env` 파일의 `OPENAI_API_KEY` 값 수정:

```env
OPENAI_API_KEY=sk-proj-your-actual-key-here
```

---

### 7️⃣ 경로 확인 방법

현재 디렉토리의 절대 경로를 확인하려면:

#### Mac/Linux:
```bash
pwd
```

#### Windows (PowerShell):
```powershell
Get-Location
```

#### Windows (CMD):
```cmd
cd
```

---

## ▶️ 실행 방법 (How to Run)

### 대시보드 실행

```bash
streamlit run Test_Dashboard.py
```

브라우저가 자동으로 열리지 않으면, 터미널에 표시된 URL로 접속:
- Local URL: `http://localhost:8501`
- Network URL: `http://192.168.x.x:8501`

---

## 🧪 API 키 테스트

OpenAI API 키가 정상적으로 작동하는지 테스트:

```bash
python Test_API_KEY.py
```

---

## 🛠️ 문제 해결 (Troubleshooting)

### ❌ "ModuleNotFoundError: No module named 'xxx'"

```bash
pip install -r requirements.txt
```

### ❌ "FileNotFoundError: [Errno 2] No such file or directory"

- `.env` 파일의 경로가 올바른지 확인
- 경로는 **절대 경로**로 입력 (예: `/Users/name/...` 또는 `C:/Users/...`)
- Windows 사용자: 백슬래시(`\`) 대신 슬래시(`/`) 사용

### ❌ "OpenAI API 키가 설정되지 않았습니다"

- `.env` 파일에 `OPENAI_API_KEY` 값이 올바르게 설정되었는지 확인
- API 키 앞뒤에 따옴표 없이 입력

### ❌ 모델 파일을 찾을 수 없음

- `MODEL_PATH` 경로가 올바른지 확인
- `best_model_pe.keras` 파일이 실제로 존재하는지 확인

---

## 📁 프로젝트 구조

```
Mini_PJT2/
├── .env                      # 환경 변수 설정 (직접 생성)
├── .env.example              # 환경 변수 예시
├── Test_Dashboard.py         # 메인 대시보드
├── Test_API_KEY.py          # API 키 테스트
├── config.py                # 설정 파일
├── ransomware_model.py      # 모델 클래스
├── feature_extractor.py     # 특징 추출
├── best_model_pe.keras      # 학습된 모델
├── requirements.txt         # 필요한 패키지 목록
├── logs/                    # 로그 저장 폴더
├── reports/                 # 보고서 저장 폴더
└── test_files/              # 테스트 파일 폴더
```

---

## 💡 팁

1. **상대 경로 vs 절대 경로**
   - `.env` 파일에는 반드시 **절대 경로** 사용
   - 상대 경로 (예: `./test_files`) 는 작동하지 않을 수 있음

2. **경로 구분자**
   - Windows: `/` 또는 `\\` (단, `/` 권장)
   - Mac/Linux: `/`

3. **API 키 보안**
   - `.env` 파일은 Git에 커밋하지 마세요
   - `.gitignore`에 `.env`가 포함되어 있는지 확인

4. **가상환경 사용 권장**
   - 프로젝트별로 독립된 Python 환경 유지
   - 패키지 충돌 방지

---

## 📞 도움이 필요하신가요?

- 이슈 등록: GitHub Issues
- 문서 확인: `README.md`

---

**작성일**: 2025-11-19
**버전**: 1.0
