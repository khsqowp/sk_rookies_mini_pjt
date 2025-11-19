# watcher.py
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from feature_extractor import extract_pe_header_features
from ransomware_model import RansomwareModel
from action_handler import ask_and_delete_if_user_confirms


class DownloadHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.model = RansomwareModel()

    def _wait_until_download_complete(self, path: Path, timeout: float = 30.0):
        """파일 크기가 더 이상 변하지 않을 때까지 대기"""
        last_size = -1
        stable_count = 0
        start = time.time()

        while time.time() - start < timeout:
            try:
                size = path.stat().st_size
            except FileNotFoundError:
                time.sleep(1.0)
                continue

            if size == last_size:
                stable_count += 1
                if stable_count >= 3:  # 3번 연속 동일 → 완료로 간주
                    return
            else:
                stable_count = 0
                last_size = size

            time.sleep(1.0)

    def _process_file(self, path: Path):
        print(f"[+] 새 파일 감지: {path}")

        # 확장자 필터링 (필요하면 늘리거나 줄여도 됨)
        if path.suffix.lower() not in {".exe", ".dll"}:
            print(f"    → 분석 대상 아님 (확장자: {path.suffix})")
            return

        print("    → 다운로드 완료 대기 중...")
        self._wait_until_download_complete(path)
        print("    → 다운로드 완료, 분석 시작")

        try:
            features = extract_pe_header_features(path)
            result = self.model.predict_with_explanation(features)

            label = result["label"]
            prob = result["prob_ransom"]

            if label == 1:
                print(f"    ⚠ 랜섬웨어 의심 (확률: {prob:.3f})")
                if result["anomalies"]:
                    print("    이상 바이트 TOP:")
                    for a in result["anomalies"]:
                        print(
                            f"      - 바이트 {a['feature']} ({a['description']}): "
                            f"값={a['value']:.0f}, 평균={a['mean']:.2f}, z={a['z_score']:.2f}"
                        )

                ask_and_delete_if_user_confirms(path)
            else:
                print(f"    → 정상으로 판단 (랜섬웨어 확률: {prob:.3f})")

        except Exception as e:
            print(f"    [에러] 분석 실패: {e}")

    def on_created(self, event):
        if event.is_directory:
            return
        self._process_file(Path(event.src_path))

    def on_moved(self, event):
        if event.is_directory:
            return
        self._process_file(Path(event.dest_path))


def main():
    downloads = Path.home() / "Downloads"
    handler = DownloadHandler()
    observer = Observer()
    observer.schedule(handler, str(downloads), recursive=False)
    observer.start()
    print(f"[+] {downloads} 감시 시작")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
