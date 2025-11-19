# action_handler.py
from pathlib import Path
import os


def ask_and_delete_if_user_confirms(path: Path):
    ans = input("    → 이 파일을 삭제할까요? [y/N]: ").strip().lower()
    if ans == "y":
        try:
            os.remove(path)
            print("    ✅ 파일 삭제 완료")
        except Exception as e:
            print(f"    [에러] 파일 삭제 실패: {e}")
    else:
        print("    → 파일 유지")
