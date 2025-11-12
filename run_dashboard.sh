#!/bin/bash

# Mini_PJT2 - 랜섬웨어 탐지 대시보드 실행 스크립트
echo "🚀 랜섬웨어 탐지 대시보드를 시작합니다..."
echo ""

# 가상환경의 streamlit을 사용하여 대시보드 실행
SCRIPT_DIR=$(cd $(dirname $0); pwd)
"$SCRIPT_DIR/.venv/bin/streamlit" run "$SCRIPT_DIR/dashboard.py"
