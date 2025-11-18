"""
랜섬웨어 탐지 테스트 샘플 자동 생성기 (최종 버전)
하나의 파일로 3개의 .exe 파일을 자동 생성합니다.
"""

import os
import sys
import subprocess

def create_sample_files():
    """3개의 테스트 샘플 Python 파일 생성"""
    
    # Sample 1: 랜섬 노트 패턴
    sample1_code = '''import sys

RANSOM_NOTE = """
╔════════════════════════════════════════════════════════════╗
║           YOUR FILES HAVE BEEN ENCRYPTED                   ║
╚════════════════════════════════════════════════════════════╝

[TEST FILE - NO ACTUAL ENCRYPTION]

All your important files have been encrypted with military-grade
encryption algorithm.

TO DECRYPT YOUR FILES:
1. Send 0.5 BTC to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
2. Email your unique ID to: recovery@darkweb-fake.onion
3. Wait for decryption key

YOUR UNIQUE ID: TEST-ABC123XYZ789

WARNING: Do not try to decrypt files yourself!
Do not restart your computer!
Do not contact authorities!

=== THIS IS A TEST FILE FOR SECURITY RESEARCH ===
"""

def main():
    print("="*60)
    print("RANSOMWARE DETECTION TEST - SAMPLE 1")
    print("="*60)
    print("\\nThis is a HARMLESS test file.")
    print("Contains: Ransom note, Bitcoin address, threat messages")
    print("\\nNo actual malicious activity will occur.\\n")
    print(RANSOM_NOTE)
    input("\\nPress Enter to exit...")

if __name__ == "__main__":
    main()
'''

    # Sample 2: 암호화 패턴
    sample2_code = '''import sys
import os

# 랜섬웨어가 흔히 사용하는 암호화 관련 import (실제로는 사용 안 함)
# from Crypto.Cipher import AES
# import hashlib
# import base64

TARGET_EXTENSIONS = [
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.pdf', '.txt', '.jpg', '.jpeg', '.png', '.gif',
    '.zip', '.rar', '.sql', '.db', '.mp3', '.mp4',
    '.avi', '.mov', '.wav', '.psd', '.ai', '.dwg'
]

ENCRYPTED_EXTENSION = '.locked'
RANSOM_NOTE_FILENAME = 'HOW_TO_DECRYPT.txt'
EXCLUDED_DIRS = ['Windows', 'Program Files', 'Program Files (x86)']
ENCRYPTION_KEY = b'TEST_KEY_NOT_REAL_0123456789ABCDEF'

def main():
    print("="*60)
    print("RANSOMWARE DETECTION TEST - SAMPLE 2")
    print("="*60)
    print("\\nThis is a HARMLESS test file.")
    print("Contains: Crypto imports, file extension lists, encryption patterns")
    print("\\nNo actual malicious activity will occur.\\n")
    
    print(f"Target file extensions: {len(TARGET_EXTENSIONS)} types")
    print(f"Encrypted extension: {ENCRYPTED_EXTENSION}")
    print(f"Ransom note filename: {RANSOM_NOTE_FILENAME}")
    print(f"Encryption key length: {len(ENCRYPTION_KEY)} bytes")
    
    print("\\n[INFO] This file only contains ransomware signatures.")
    print("[INFO] No files will be encrypted or modified.")
    
    input("\\nPress Enter to exit...")

if __name__ == "__main__":
    main()
'''

    # Sample 3: 네트워크 패턴
    sample3_code = '''import sys
import os

C2_SERVERS = [
    'http://darkweb-c2-fake.onion',
    'http://192.168.1.100:8080/control',
    'https://command-server-test.com/api'
]

REGISTRY_PATHS = [
    r'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    r'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    r'HKEY_CURRENT_USER\\Software\\TestRansomware'
]

PROCESSES_TO_KILL = [
    'sql', 'oracle', 'ocssd', 'dbsnmp', 'synctime',
    'mydesktopqos', 'agntsvc', 'isqlplussvc', 'xfssvccon',
    'mydesktopservice', 'ocautoupds', 'encsvc', 'firefox',
    'tbirdconfig', 'ocomm', 'mysqld', 'steam', 'thebat',
    'thunderbird', 'outlook'
]

LISTENING_PORT = 4444
EXFILTRATION_PORT = 8888

PAYLOAD_URLS = [
    'http://malicious-fake.com/payload.bin',
    'http://evil-server-test.net/decrypt_tool.exe'
]

def main():
    print("="*60)
    print("RANSOMWARE DETECTION TEST - SAMPLE 3")
    print("="*60)
    print("\\nThis is a HARMLESS test file.")
    print("Contains: C2 servers, registry keys, process names, network patterns")
    print("\\nNo actual malicious activity will occur.\\n")
    
    print(f"C&C Servers: {len(C2_SERVERS)} endpoints")
    print(f"Registry paths: {len(REGISTRY_PATHS)} keys")
    print(f"Target processes: {len(PROCESSES_TO_KILL)} processes")
    print(f"Network ports: {LISTENING_PORT}, {EXFILTRATION_PORT}")
    print(f"Payload URLs: {len(PAYLOAD_URLS)} sources")
    
    print("\\n[INFO] This file only contains ransomware behavioral patterns.")
    print("[INFO] No network connections or system modifications will occur.")
    
    input("\\nPress Enter to exit...")

if __name__ == "__main__":
    main()
'''

    # 현재 디렉토리에 파일 작성 (경로 문제 해결)
    samples = {
        'test_ransom_sample_1.py': sample1_code,
        'test_ransom_sample_2.py': sample2_code,
        'test_ransom_sample_3.py': sample3_code
    }
    
    for filename, code in samples.items():
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(code)
    
    return list(samples.keys())


def check_python():
    """Python 설치 확인"""
    try:
        result = subprocess.run([sys.executable, '--version'], 
                              capture_output=True, text=True)
        version = result.stdout.strip() if result.stdout else result.stderr.strip()
        print(f"✓ Python 확인: {version}")
        return True
    except Exception as e:
        print(f"✗ Python 확인 실패: {e}")
        print("  https://www.python.org/downloads/ 에서 다운로드하세요.")
        return False


def install_pyinstaller():
    """PyInstaller 설치"""
    print("\n[단계 1/4] PyInstaller 설치 중...")
    try:
        result = subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller'], 
                      check=True, capture_output=True, text=True)
        print("✓ PyInstaller 설치 완료")
        return True
    except subprocess.CalledProcessError as e:
        print("✗ PyInstaller 설치 실패")
        if e.stderr:
            print(f"   에러: {e.stderr[:200]}")
        return False
    except Exception as e:
        print(f"✗ PyInstaller 설치 실패: {e}")
        return False


def build_exe(python_file, exe_name):
    """개별 .exe 파일 빌드"""
    print(f"\n빌드 중: {exe_name}.exe ...")
    try:
        # python -m PyInstaller 방식으로 실행 (더 안정적)
        result = subprocess.run([
            sys.executable, '-m', 'PyInstaller',
            '--onefile',
            '--name', exe_name,
            '--noconsole',
            python_file
        ], check=True, capture_output=True, text=True)
        print(f"✓ {exe_name}.exe 빌드 완료")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {exe_name}.exe 빌드 실패")
        if e.stderr:
            error_lines = e.stderr.split('\n')
            # 마지막 몇 줄의 에러만 출력
            for line in error_lines[-5:]:
                if line.strip():
                    print(f"   {line}")
        return False
    except Exception as e:
        print(f"✗ {exe_name}.exe 빌드 실패: {e}")
        return False


def cleanup_temp_files(sample_files):
    """임시 파일 정리"""
    print("\n[정리] 임시 파일을 삭제하시겠습니까? (y/n): ", end='')
    try:
        choice = input().lower()
        if choice == 'y':
            # Python 샘플 파일 삭제
            for f in sample_files:
                try:
                    os.remove(f)
                    print(f"  삭제: {f}")
                except Exception as e:
                    print(f"  삭제 실패: {f} - {e}")
            
            # .spec 파일 삭제
            for f in ['ransom_test_1.spec', 'ransom_test_2.spec', 'ransom_test_3.spec']:
                try:
                    if os.path.exists(f):
                        os.remove(f)
                        print(f"  삭제: {f}")
                except Exception as e:
                    print(f"  삭제 실패: {f} - {e}")
            
            print("✓ 정리 완료")
        else:
            print("  임시 파일을 유지합니다.")
    except:
        print("  임시 파일을 유지합니다.")


def main():
    print("="*70)
    print(" 랜섬웨어 탐지 테스트 샘플 자동 생성기")
    print("="*70)
    print("\n이 스크립트는 3개의 테스트용 .exe 파일을 자동으로 생성합니다.")
    print("실제 악성 행위는 하지 않으며, 탐지 시스템 테스트용입니다.")
    print("\n⚠️  주의: Windows Defender가 파일을 삭제할 수 있습니다!")
    print("         실시간 보호를 일시 중지하거나 폴더를 예외 처리하세요.\n")
    
    # 현재 작업 디렉토리 출력
    current_dir = os.getcwd()
    print(f"작업 디렉토리: {current_dir}\n")
    
    input("계속하려면 Enter를 누르세요...")
    print()
    
    # Python 확인
    if not check_python():
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    # PyInstaller 설치
    if not install_pyinstaller():
        print("\n관리자 권한으로 명령 프롬프트를 실행하고 다시 시도하세요.")
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    # 샘플 파일 생성
    print("\n[단계 2/4] 테스트 샘플 파일 생성 중...")
    sample_files = create_sample_files()
    print(f"✓ {len(sample_files)}개 샘플 파일 생성 완료")
    for f in sample_files:
        print(f"  - {f}")
    
    # .exe 파일 빌드
    print("\n[단계 3/4] .exe 파일 빌드 중...")
    print("(각 파일당 약 30초~1분 소요)")
    
    builds = [
        ('test_ransom_sample_1.py', 'ransom_test_1'),
        ('test_ransom_sample_2.py', 'ransom_test_2'),
        ('test_ransom_sample_3.py', 'ransom_test_3')
    ]
    
    success_count = 0
    failed_builds = []
    
    for py_file, exe_name in builds:
        if build_exe(py_file, exe_name):
            success_count += 1
        else:
            failed_builds.append(exe_name)
    
    # 결과 출력
    print("\n" + "="*70)
    print(" 빌드 완료!")
    print("="*70)
    print(f"\n성공: {success_count}/3개 파일")
    
    if success_count > 0:
        # 현재 작업 디렉토리의 dist 폴더 경로
        dist_path = os.path.join(current_dir, 'dist')
        
        print(f"\n생성된 파일 위치:")
        print(f"{dist_path}\\")
        
        # 실제로 생성된 파일 확인
        if os.path.exists(dist_path):
            exe_files = [f for f in os.listdir(dist_path) if f.endswith('.exe')]
            for exe_file in sorted(exe_files):
                full_path = os.path.join(dist_path, exe_file)
                size = os.path.getsize(full_path) / (1024*1024)  # MB
                print(f"  ✓ {exe_file} ({size:.1f} MB)")
                print(f"     {full_path}")
        
        print("\n⚠️  중요 주의사항:")
        print("  1. 이 파일들은 안티바이러스에 탐지될 수 있습니다 (정상)")
        print("  2. 격리된 테스트 환경에서만 사용하세요")
        print("  3. VirusTotal 등 공개 플랫폼에 업로드 금지")
        print("  4. 실제 악성 행위는 하지 않습니다")
        
        print("\n테스트 방법:")
        print(f"  1. {dist_path} 폴더로 이동")
        print("  2. 각 .exe 파일 실행 (안전한 환경에서)")
        print("  3. 탐지 시스템으로 스캔")
        
    else:
        print("\n✗ 모든 빌드 실패")
        print("\n해결 방법:")
        print("  1. 관리자 권한으로 명령 프롬프트 실행")
        print("  2. pip install pyinstaller 실행")
        print("  3. 이 스크립트를 다시 실행")
    
    if failed_builds:
        print(f"\n실패한 빌드: {', '.join(failed_builds)}")
    
    # 임시 파일 정리
    if success_count > 0:
        print("\n[단계 4/4] 정리 작업")
        cleanup_temp_files(sample_files)
    
    print("\n" + "="*70)
    input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()
    