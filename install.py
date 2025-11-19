#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
테스트용 .exe 파일 자동 생성 스크립트
이 파일 하나만 실행하면 모든 것이 자동으로 처리됩니다.
"""
import subprocess
import sys
from pathlib import Path
import shutil

# 테스트 프로그램들
PROGRAMS = {
    'test_simple.py': '''import time
import sys

print("=" * 50)
print("테스트 프로그램 #1 - 간단한 계산")
print("=" * 50)
print()

numbers = list(range(1, 11))
print(f"숫자: {numbers}")
print(f"합계: {sum(numbers)}")
print(f"평균: {sum(numbers)/len(numbers):.2f}")
print()

print("피보나치 수열 (10개):")
fib = [0, 1]
for i in range(8):
    fib.append(fib[-1] + fib[-2])
print(fib)
print()

print("5초 후 종료됩니다...")
time.sleep(5)
''',
    'test_sysinfo.py': '''import platform
import datetime
import os
import sys
import time

print("=" * 50)
print("테스트 프로그램 #2 - 시스템 정보")
print("=" * 50)
print()

print(f"운영체제: {platform.system()} {platform.release()}")
print(f"프로세서: {platform.processor()}")
print(f"Python 버전: {sys.version.split()[0]}")
print(f"현재 시간: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"현재 경로: {os.getcwd()}")
print()

print("이 프로그램은 완전히 무해합니다.")
print("테스트 목적으로만 사용됩니다.")
print()
print("5초 후 종료됩니다...")
time.sleep(5)
''',
    'test_hello.py': '''import time

print("=" * 50)
print("Hello World - 테스트 프로그램")
print("=" * 50)
print()
print("이 프로그램은 아무런 해로운 작업을 하지 않습니다.")
print("랜섬웨어 탐지 시스템 테스트용입니다.")
print()
print("프로그램 버전: 1.0")
print("제작: SK Shielders 랜섬웨어 탐지 프로젝트")
print()

print("3초 후 종료됩니다...")
time.sleep(3)
print("종료합니다.")
'''
}

def main():
    print("=" * 70)
    print("테스트용 .exe 파일 자동 생성 스크립트")
    print("=" * 70)
    print()
    print("이 스크립트는 다음을 자동으로 수행합니다:")
    print("  1. PyInstaller 설치 확인 및 설치")
    print("  2. 테스트 Python 스크립트 생성")
    print("  3. .exe 파일 빌드")
    print("  4. 정리 및 확인")
    print()
    
    # 1. Python 파일 생성
    print("[1/4] Python 스크립트 생성 중...")
    for filename, code in PROGRAMS.items():
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(code)
        print(f"  ✅ {filename}")
    print()
    
    # 2. PyInstaller 설치 확인
    print("[2/4] PyInstaller 확인 중...")
    try:
        import PyInstaller
        print("  ✅ 이미 설치되어 있습니다.")
    except ImportError:
        print("  ⚠️  PyInstaller가 없습니다. 설치 중... (30초 정도 소요)")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "pyinstaller"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("  ✅ 설치 완료!")
        except Exception as e:
            print(f"  ❌ 설치 실패: {e}")
            print("\n수동으로 설치하세요: pip install pyinstaller")
            return
    print()
    
    # 3. .exe 생성
    print("[3/4] .exe 파일 생성 중...")
    print("  (각 파일마다 30-60초 소요됩니다. 잠시 기다려주세요...)")
    print()
    
    output_dir = Path("test_executables")
    output_dir.mkdir(exist_ok=True)
    
    success_count = 0
    for filename in PROGRAMS.keys():
        exe_name = filename.replace('.py', '')
        print(f"  🔨 {filename} 빌드 중...", end=' ', flush=True)
        
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--clean",
            "--log-level", "ERROR",
            "--distpath", str(output_dir),
            "--workpath", "build_temp",
            "--specpath", "build_temp",
            "--name", exe_name,
            filename
        ]
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True
            )
            
            exe_file = output_dir / f"{exe_name}.exe"
            if result.returncode == 0 and exe_file.exists():
                size = exe_file.stat().st_size / 1024 / 1024  # MB
                print(f"✅ ({size:.1f} MB)")
                success_count += 1
            else:
                print("❌ 실패")
                if result.stderr:
                    print(f"     오류: {result.stderr[:100]}")
        except Exception as e:
            print(f"❌ 오류: {e}")
    
    print()
    
    # 4. 정리
    print("[4/4] 임시 파일 정리 중...")
    try:
        shutil.rmtree("build_temp", ignore_errors=True)
        print("  ✅ 정리 완료")
    except:
        print("  ⚠️  일부 파일 정리 실패 (무시 가능)")
    print()
    
    # 결과 출력
    print("=" * 70)
    if success_count == len(PROGRAMS):
        print("✅ 모든 .exe 파일 생성 완료!")
    elif success_count > 0:
        print(f"⚠️  {success_count}/{len(PROGRAMS)}개 파일 생성 완료")
    else:
        print("❌ .exe 파일 생성 실패")
        print("\n수동으로 시도해보세요:")
        print("  pip install pyinstaller")
        print("  python -m PyInstaller --onefile test_hello.py")
        return
    print("=" * 70)
    print()
    
    # 생성된 파일 목록
    exe_files = list(output_dir.glob("*.exe"))
    if exe_files:
        print(f"📁 생성된 .exe 파일 위치: {output_dir.absolute()}")
        print()
        print("생성된 파일:")
        for exe in exe_files:
            size = exe.stat().st_size / 1024 / 1024
            print(f"  - {exe.name} ({size:.1f} MB)")
        print()
        
        print("실행 방법:")
        print("  1. 탐색기에서 test_executables 폴더를 열고 더블클릭")
        print("  2. 명령창에서: test_executables\\test_hello.exe")
        print()
        
        print("랜섬웨어 탐지 시스템으로 테스트:")
        print("  python watcher.py 실행 후")
        print("  .exe 파일을 Downloads 폴더로 복사")
        print()
    
    print("⚠️  주의사항:")
    print("  • 이 프로그램들은 완전히 무해합니다")
    print("  • Windows Defender가 경고할 수 있습니다 (정상)")
    print("  • 테스트 목적으로만 사용하세요")
    print()

if __name__ == "__main__":
    main()