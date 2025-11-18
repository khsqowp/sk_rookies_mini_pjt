# watcher.py

import time
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from config import DOWNLOAD_DIR, ANALYSIS_EXTENSIONS, TEMP_EXTENSIONS
from feature_extractor import extract_features_from_file
from ransomware_model import RansomwareModel
from action_handler import handle_action


def wait_for_complete_download(path: Path, retries: int = 10, interval: float = 1.0) -> bool:
    """
    파일 크기가 더 이상 변하지 않을 때까지 기다림.
    - retries * interval 초 동안 시도
    - True: 안정됨, False: 계속 변하거나 못 읽음
    """
    last_size = -1
    for _ in range(retries):
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            time.sleep(interval)
            continue

        if size > 0 and size == last_size:
            return True  # 크기가 안 바뀌면 다운로드 끝난 걸로 판단

        last_size = size
        time.sleep(interval)
    return False


class DownloadHandler(FileSystemEventHandler):
    def __init__(self, model: RansomwareModel):
        self.model = model

    def _process_file(self, path: Path):
        suffix = path.suffix.lower()

        # 1) 브라우저 임시 파일은 아예 무시
        if suffix in TEMP_EXTENSIONS:
            print(f"\n[+] 임시 다운로드 파일 감지 (무시): {path}")
            return

        print(f"\n[+] 새 파일 감지: {path}")

        # 2) 우리가 분석하고 싶은 종류만 대상
        if suffix not in ANALYSIS_EXTENSIONS:
            print(f"    → 분석 대상 아님 (확장자: {suffix})")
            return

        # 3) 파일이 다 받아질 때까지 잠깐 기다리기
        print("    → 다운로드 완료 대기 중...")
        if not wait_for_complete_download(path):
            print("    → 일정 시간 안에 파일 크기가 안정되지 않음. 분석 건너뜀.")
            return

        # 4) 피처 추출
        try:
            features = extract_features_from_file(path)
        except Exception as e:
            print(f"    → 피처 추출 실패: {e}")
            return

        # 5) 모델 예측 + 이상 피처 설명
        result = self.model.predict_with_explanation(features)
        label = result["label"]
        prob = result["prob_ransom"]
        anomalies = result["anomalies"]

        if label == 0:
            print(f"    → 정상으로 판단 (랜섬웨어 확률: {prob:.3f})")
            handle_action(path, features, result, anomalies, action="log")
            return

        print(f"    ⚠ 랜섬웨어 의심! (확률: {prob:.3f})")
        if anomalies:
            print("    → 이상 피처 TOP:")
            for a in anomalies:
                print(
                    f"      - {a['feature']} ({a['description']}): "
                    f"값={a['value']:.2f}, 평균={a['mean']:.2f}, z={a['z_score']:.2f}"
                )

        # 6) 사용자에게 삭제 여부 질문
        while True:
            ans = input("이 파일을 삭제할까요? (yes/no): ").strip().lower()
            if ans in ("yes", "y"):
                user_action = "delete"
                break
            elif ans in ("no", "n"):
                user_action = "log"
                break
            else:
                print("yes 또는 no로 입력해 주세요.")

        entry = handle_action(
            file_path=path,
            features=features,
            model_result=result,
            anomalies=anomalies,
            action=user_action,
        )
        print(f"\n[로그 기록 완료] action={entry['action']}, result={entry['action_result']}")

    # on_created: 새 파일 생겼을 때
    def on_created(self, event):
        if event.is_directory:
            return
        self._process_file(Path(event.src_path))

    # on_moved: 브라우저가 .tmp → 실제 파일명으로 바꿀 때도 처리
    def on_moved(self, event):
        if event.is_directory:
            return
        self._process_file(Path(event.dest_path))


def main():
    model = RansomwareModel()

    event_handler = DownloadHandler(model)
    observer = Observer()
    observer.schedule(event_handler, str(DOWNLOAD_DIR), recursive=False)
    observer.start()

    print(f"[감시 시작] {DOWNLOAD_DIR} 에서 새로 생성/이동되는 파일을 모니터링 중... (Ctrl+C 종료)")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
