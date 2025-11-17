import os
import pickle
import pandas as pd
import pefile
from sklearn.ensemble import RandomForestClassifier

class FileAnalyzer:
    """
    .exe 파일의 정적 특징을 분석하여 랜섬웨어 여부를 예측하는 클래스.
    - pefile을 사용하여 특징 추출
    - 미리 학습된 RandomForest 모델을 사용하여 예측
    """
    def __init__(self, model_path="ransomware_detection_model.pkl"):
        """
        분석기 초기화 및 모델 로드
        :param model_path: 미리 학습된 .pkl 모델 파일 경로
        """
        self.model, self.feature_columns = self._load_model(model_path)

    def _load_model(self, model_path):
        """
        .pkl 파일에서 학습된 모델과 사용된 특징(feature) 목록을 로드합니다.
        """
        if not os.path.exists(model_path):
            print(f"경고: 모델 파일({model_path})을 찾을 수 없습니다. 예측 기능이 비활성화됩니다.")
            return None, None
        try:
            with open(model_path, "rb") as f:
                model_data = pickle.load(f)
            
            if isinstance(model_data, dict) and "model" in model_data and "features" in model_data:
                print("성공: 머신러닝 모델과 특징 목록을 로드했습니다.")
                return model_data["model"], model_data["features"]
            else:
                # 이전 버전 호환성을 위해 dict가 아닌 경우도 처리
                print("성공: 머신러닝 모델을 로드했습니다 (특징 목록 미포함).")
                return model_data, None # 특징 목록이 없는 구버전 모델일 수 있음
        except Exception as e:
            print(f"오류: 모델 로드 중 문제가 발생했습니다 - {e}")
            return None, None

    def extract_features_from_file(self, file_path):
        """
        단일 .exe 파일에서 PE(Portable Executable) 특징을 추출합니다.
        :param file_path: 분석할 .exe 파일의 경로
        :return: 특징들이 담긴 딕셔너리, 또는 오류 발생 시 None
        """
        try:
            pe = pefile.PE(file_path)
            
            # 엔트로피 계산 (섹션이 없는 경우 방지)
            section_entropies = [section.get_entropy() for section in pe.sections if section.get_entropy() > 0]
            
            features = {
                "ImageBase": pe.OPTIONAL_HEADER.ImageBase,
                "SizeOfImage": pe.OPTIONAL_HEADER.SizeOfImage,
                "CheckSum": pe.OPTIONAL_HEADER.CheckSum,
                "Subsystem": pe.OPTIONAL_HEADER.Subsystem,
                "MajorSubsystemVersion": pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                "MinorSubsystemVersion": pe.OPTIONAL_HEADER.MinorSubsystemVersion,
                "SectionsMaxEntropy": max(section_entropies) if section_entropies else 0,
                "SectionsMinEntropy": min(section_entropies) if section_entropies else 0,
                "SectionsMeanEntropy": sum(section_entropies) / len(section_entropies) if section_entropies else 0,
            }
            return features
        except Exception as e:
            print(f"오류: '{os.path.basename(file_path)}' 파일 처리 중 오류 발생 - {e}")
            return None

    def predict_file(self, file_path, threshold=0.5):
        """
        단일 .exe 파일을 분석하고 랜섬웨어 여부를 예측합니다.
        :param file_path: 분석할 .exe 파일의 경로
        :param threshold: 랜섬웨어로 판단할 확률 임계값
        :return: 분석 결과 (파일명, 확률, 예측 결과 등) 딕셔너리
        """
        if self.model is None or self.feature_columns is None:
            return {
                "FileName": os.path.basename(file_path),
                "Error": "모델이 로드되지 않아 예측을 수행할 수 없습니다."
            }

        features = self.extract_features_from_file(file_path)
        if not features:
            return {
                "FileName": os.path.basename(file_path),
                "Error": "파일에서 특징을 추출할 수 없습니다."
            }

        # DataFrame으로 변환 및 특징 순서 맞추기
        features_df = pd.DataFrame([features])
        for col in self.feature_columns:
            if col not in features_df.columns:
                features_df[col] = 0  # 학습 시 사용된 특징이 파일에 없으면 0으로 채움
        
        feature_data = features_df[self.feature_columns]

        try:
            # 랜섬웨어일 확률 예측
            probability = self.model.predict_proba(feature_data)[:, 1][0]
            is_ransomware = probability > threshold

            result = {
                "FileName": os.path.basename(file_path),
                "Probability": probability,
                "IsRansomware": is_ransomware,
                "Result": "Ransomware" if is_ransomware else "Safe",
                "Features": features
            }
            return result
        except Exception as e:
            print(f"오류: 예측 중 문제가 발생했습니다 - {e}")
            return {
                "FileName": os.path.basename(file_path),
                "Error": f"예측 실패: {e}"
            }

if __name__ == '__main__':
    # 이 파일이 직접 실행될 때 테스트를 위한 코드
    # 사용자는 ransomware_detection_model.pkl 파일이 필요합니다.
    # 이 모델은 PE 특징으로 학습된 RandomForestClassifier여야 합니다.
    
    # 1. 테스트용 가짜 모델(.pkl) 파일 생성 (실제로는 이 파일이 이미 있어야 함)
    if not os.path.exists("ransomware_detection_model.pkl"):
        print("테스트용 가짜 모델 파일을 생성합니다: 'ransomware_detection_model.pkl'")
        from sklearn.datasets import make_classification
        X, y = make_classification(n_samples=100, n_features=9, n_informative=5, n_redundant=0, random_state=42)
        _model = RandomForestClassifier(random_state=42)
        _feature_names = [
            "ImageBase", "SizeOfImage", "CheckSum", "Subsystem", "MajorSubsystemVersion", 
            "MinorSubsystemVersion", "SectionsMaxEntropy", "SectionsMinEntropy", "SectionsMeanEntropy"
        ]
        _model.fit(X, y)
        model_data = {"model": _model, "features": _feature_names}
        with open("ransomware_detection_model.pkl", "wb") as f:
            pickle.dump(model_data, f)

    # 2. 테스트용 가짜 .exe 파일 생성 (pefile이 분석할 수 있는 최소한의 구조)
    if not os.path.exists("test.exe"):
        print("테스트용 가짜 .exe 파일을 생성합니다: 'test.exe'")
        pe = pefile.PE()
        pe.set_bytes(b'MZ' + b'\x00'*58 + b'\x04\x00\x00\x00' + b'\x00'*16 + b'PE\x00\x00' + b'\x01\x4c' + b'\x01\x00' + b'\x00'*20 + b'\xe0\x00' + b'\x0b\x01' + b'\x00'*52 + b'\x00\x10\x00\x00' + b'\x00\x10\x00\x00' + b'\x00 \x20\x00\x00' + b'\x00\x00\x40\x00' + b'\x00'*132)
        pe.write("test.exe")

    # 3. 분석기 인스턴스 생성 및 테스트
    analyzer = FileAnalyzer()
    if analyzer.model:
        analysis_result = analyzer.predict_file("test.exe")
        print("\n--- 분석 결과 ---")
        import json
        print(json.dumps(analysis_result, indent=2))
        
        # 4. 테스트 파일 삭제
        os.remove("test.exe")
        # os.remove("ransomware_detection_model.pkl") # 모델은 계속 사용을 위해 남겨둘 수 있음
    else:
        print("\n모델이 로드되지 않아 테스트를 진행할 수 없습니다.")
