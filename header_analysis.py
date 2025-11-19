# header_analysis_tool.py
"""
PE 헤더 바이트 중요도 분석 및 랜섬웨어 판별 이유 설명 도구
"""
import json
from pathlib import Path
from typing import Dict, List, Tuple
import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib import font_manager
import joblib

from config import MODEL_PATH, BENIGN_STATS_PATH, FEATURES_PATH

# 한글 폰트 설정
plt.rcParams['font.family'] = 'Malgun Gothic'
plt.rcParams['axes.unicode_minus'] = False


class HeaderAnalyzer:
    """PE 헤더 분석 도구"""
    
    def __init__(self):
        """초기화 및 모델/통계 로딩"""
        self.model = joblib.load(MODEL_PATH)
        self.features = json.loads(FEATURES_PATH.read_text(encoding="utf-8"))
        self.benign_stats = json.loads(BENIGN_STATS_PATH.read_text(encoding="utf-8"))
        
        print(f"✅ 모델 로딩 완료: {len(self.features)}개 피처 사용")
    
    def get_feature_importance(self, top_k: int = 50) -> pd.DataFrame:
        """
        Random Forest의 피처 중요도 추출
        
        Args:
            top_k: 상위 몇 개 피처를 반환할지
        
        Returns:
            DataFrame with columns: feature, importance, mean, std
        """
        if not hasattr(self.model, 'feature_importances_'):
            raise ValueError("모델이 feature_importances_ 속성을 지원하지 않습니다.")
        
        importances = self.model.feature_importances_
        
        results = []
        for feature, importance in zip(self.features, importances):
            stat = self.benign_stats.get(feature, {})
            results.append({
                'feature': feature,
                'byte_position': int(feature),
                'importance': importance,
                'benign_mean': stat.get('mean', 0),
                'benign_std': stat.get('std', 0)
            })
        
        df = pd.DataFrame(results)
        df = df.sort_values('importance', ascending=False).reset_index(drop=True)
        
        return df.head(top_k)
    
    def analyze_file_anomalies(
        self, 
        file_features: Dict[str, float],
        top_k: int = 20
    ) -> pd.DataFrame:
        """
        특정 파일의 이상 바이트 분석
        
        Args:
            file_features: 파일에서 추출한 피처 딕셔너리
            top_k: 상위 몇 개 이상 바이트를 반환할지
        
        Returns:
            DataFrame with anomaly analysis
        """
        results = []
        
        for feature in self.features:
            if feature not in self.benign_stats:
                continue
            
            value = float(file_features.get(feature, 0))
            mean = self.benign_stats[feature]['mean']
            std = self.benign_stats[feature]['std']
            
            z_score = (value - mean) / std if std > 0 else 0
            
            results.append({
                'feature': feature,
                'byte_position': int(feature),
                'value': value,
                'benign_mean': mean,
                'benign_std': std,
                'z_score': z_score,
                'abs_z_score': abs(z_score),
                'deviation': value - mean
            })
        
        df = pd.DataFrame(results)
        df = df.sort_values('abs_z_score', ascending=False).reset_index(drop=True)
        
        return df.head(top_k)
    
    def predict_and_explain(
        self, 
        file_features: Dict[str, float]
    ) -> Dict:
        """
        파일 예측 및 상세 설명
        
        Args:
            file_features: 파일에서 추출한 피처 딕셔너리
        
        Returns:
            예측 결과 및 설명 딕셔너리
        """
        # 피처 벡터 생성
        X = np.array([[float(file_features.get(f, 0)) for f in self.features]])
        
        # 예측
        prediction = int(self.model.predict(X)[0])
        
        if hasattr(self.model, 'predict_proba'):
            prob = float(self.model.predict_proba(X)[0][1])
        else:
            prob = float(prediction)
        
        # 이상 바이트 분석
        anomalies_df = self.analyze_file_anomalies(file_features, top_k=20)
        
        # 피처 중요도와 이상값을 결합한 위험도 계산
        importance_df = self.get_feature_importance(top_k=len(self.features))
        importance_dict = dict(zip(importance_df['feature'], importance_df['importance']))
        
        risk_scores = []
        for _, row in anomalies_df.iterrows():
            feature = row['feature']
            importance = importance_dict.get(feature, 0)
            risk_score = abs(row['z_score']) * importance
            risk_scores.append(risk_score)
        
        anomalies_df['importance'] = anomalies_df['feature'].map(importance_dict)
        anomalies_df['risk_score'] = risk_scores
        anomalies_df = anomalies_df.sort_values('risk_score', ascending=False).reset_index(drop=True)
        
        return {
            'prediction': prediction,
            'label': '랜섬웨어' if prediction == 1 else '정상',
            'probability': prob,
            'anomalies': anomalies_df.to_dict('records'),
            'top_risk_features': anomalies_df.head(10).to_dict('records')
        }
    
    def visualize_feature_importance(
        self, 
        top_k: int = 30,
        save_path: Path = None
    ):
        """피처 중요도 시각화"""
        df = self.get_feature_importance(top_k)
        
        fig, ax = plt.subplots(figsize=(12, 8))
        
        bars = ax.barh(df['feature'].astype(str), df['importance'], color='steelblue')
        ax.set_xlabel('중요도', fontsize=12)
        ax.set_ylabel('헤더 바이트 위치', fontsize=12)
        ax.set_title(f'랜섬웨어 탐지 상위 {top_k}개 중요 헤더 바이트', fontsize=14, fontweight='bold')
        ax.invert_yaxis()
        
        # 값 표시
        for i, (bar, imp) in enumerate(zip(bars, df['importance'])):
            ax.text(imp, bar.get_y() + bar.get_height()/2, 
                   f'{imp:.4f}', 
                   va='center', ha='left', fontsize=9)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"✅ 그래프 저장: {save_path}")
        
        plt.show()
    
    def visualize_anomalies(
        self,
        file_features: Dict[str, float],
        top_k: int = 20,
        save_path: Path = None
    ):
        """특정 파일의 이상 바이트 시각화"""
        df = self.analyze_file_anomalies(file_features, top_k)
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))
        
        # Z-score 분포
        colors = ['red' if z > 0 else 'blue' for z in df['z_score']]
        ax1.barh(df['feature'].astype(str), df['z_score'], color=colors, alpha=0.7)
        ax1.set_xlabel('Z-Score', fontsize=12)
        ax1.set_ylabel('헤더 바이트 위치', fontsize=12)
        ax1.set_title(f'상위 {top_k}개 이상 바이트 (Z-Score)', fontsize=14, fontweight='bold')
        ax1.axvline(x=0, color='black', linestyle='--', linewidth=1)
        ax1.invert_yaxis()
        
        # 실제 값 vs 평균 비교
        x = np.arange(len(df))
        width = 0.35
        
        ax2.bar(x - width/2, df['value'], width, label='실제 값', color='coral', alpha=0.8)
        ax2.bar(x + width/2, df['benign_mean'], width, label='정상 평균', color='skyblue', alpha=0.8)
        ax2.set_xlabel('헤더 바이트 위치', fontsize=12)
        ax2.set_ylabel('바이트 값', fontsize=12)
        ax2.set_title(f'실제 값 vs 정상 평균 비교', fontsize=14, fontweight='bold')
        ax2.set_xticks(x)
        ax2.set_xticklabels(df['feature'].astype(str), rotation=45, ha='right')
        ax2.legend()
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"✅ 그래프 저장: {save_path}")
        
        plt.show()
    
    def compare_benign_vs_ransomware(
        self,
        csv_path: Path,
        top_k: int = 20,
        save_path: Path = None
    ):
        """정상 파일과 랜섬웨어의 헤더 바이트 분포 비교"""
        df = pd.read_csv(csv_path)
        
        byte_cols = sorted([c for c in df.columns if c.isdigit()], key=lambda x: int(x))
        
        # 중요한 피처만 선택
        important_features = self.features[:top_k]
        
        benign = df[df['GR'] == 0]
        ransomware = df[df['GR'] == 1]
        
        fig, axes = plt.subplots(5, 4, figsize=(20, 15))
        axes = axes.ravel()
        
        for i, feature in enumerate(important_features):
            if i >= 20:
                break
            
            ax = axes[i]
            
            if feature in df.columns:
                benign_vals = benign[feature].astype(float)
                ransom_vals = ransomware[feature].astype(float)
                
                ax.hist(benign_vals, bins=30, alpha=0.6, label='정상', color='blue', density=True)
                ax.hist(ransom_vals, bins=30, alpha=0.6, label='랜섬웨어', color='red', density=True)
                
                ax.set_title(f'Byte {feature}', fontsize=10, fontweight='bold')
                ax.set_xlabel('바이트 값', fontsize=9)
                ax.set_ylabel('밀도', fontsize=9)
                ax.legend(fontsize=8)
                ax.grid(alpha=0.3)
        
        plt.suptitle('정상 파일 vs 랜섬웨어: 중요 헤더 바이트 분포 비교', 
                    fontsize=16, fontweight='bold', y=1.00)
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"✅ 그래프 저장: {save_path}")
        
        plt.show()
    
    def generate_report(
        self,
        file_features: Dict[str, float],
        filename: str = "unknown.exe"
    ) -> str:
        """상세 분석 리포트 생성"""
        result = self.predict_and_explain(file_features)
        
        report = []
        report.append("=" * 80)
        report.append("PE 헤더 랜섬웨어 분석 리포트")
        report.append("=" * 80)
        report.append(f"\n파일명: {filename}")
        report.append(f"판정: {result['label']}")
        report.append(f"랜섬웨어 확률: {result['probability']:.2%}")
        
        if result['prediction'] == 1:
            report.append("\n" + "=" * 80)
            report.append("⚠️  랜섬웨어로 의심되는 이유 (상위 10개 위험 요소)")
            report.append("=" * 80)
            
            for i, feature_info in enumerate(result['top_risk_features'], 1):
                report.append(f"\n[{i}] 헤더 바이트 위치: {feature_info['byte_position']}")
                report.append(f"    • 실제 값: {feature_info['value']:.2f}")
                report.append(f"    • 정상 평균: {feature_info['benign_mean']:.2f}")
                report.append(f"    • 표준편차: {feature_info['benign_std']:.2f}")
                report.append(f"    • Z-Score: {feature_info['z_score']:.2f}")
                report.append(f"    • 피처 중요도: {feature_info['importance']:.4f}")
                report.append(f"    • 위험도 점수: {feature_info['risk_score']:.4f}")
                
                # 해석
                if abs(feature_info['z_score']) > 3:
                    report.append(f"    ⚠️  극단적 이상값 (±3σ 이상)")
                elif abs(feature_info['z_score']) > 2:
                    report.append(f"    ⚠️  유의미한 이상값 (±2σ 이상)")
        else:
            report.append("\n✅ 정상 파일로 판정되었습니다.")
        
        report.append("\n" + "=" * 80)
        
        return "\n".join(report)


# ==================== 메인 실행 ====================
def main():
    """분석 도구 메인 실행"""
    
    # CSV 경로
    CSV_PATH = Path(
        r"C:\Users\sec\OneDrive\바탕 화면\SK쉴더스\ransom_dectection_model\sk_rookies_mini_pjt\Ransomware_headers.csv"
    )
    
    # 분석기 초기화
    analyzer = HeaderAnalyzer()
    
    # 1. 피처 중요도 시각화
    print("\n[1] 피처 중요도 분석")
    importance_df = analyzer.get_feature_importance(top_k=30)
    print(importance_df)
    
    output_dir = MODEL_PATH.parent / "analysis_results"
    output_dir.mkdir(exist_ok=True)
    
    analyzer.visualize_feature_importance(
        top_k=30,
        save_path=output_dir / "feature_importance.png"
    )
    
    # 2. 정상 vs 랜섬웨어 분포 비교
    print("\n[2] 정상 vs 랜섬웨어 헤더 바이트 분포 비교")
    analyzer.compare_benign_vs_ransomware(
        csv_path=CSV_PATH,
        top_k=20,
        save_path=output_dir / "distribution_comparison.png"
    )
    
    # 3. 샘플 파일 분석 (데이터셋에서 랜섬웨어 샘플 하나 선택)
    print("\n[3] 샘플 랜섬웨어 파일 분석")
    df = pd.read_csv(CSV_PATH)
    ransomware_sample = df[df['GR'] == 1].iloc[0]
    
    byte_cols = sorted([c for c in df.columns if c.isdigit()], key=lambda x: int(x))
    sample_features = {col: float(ransomware_sample[col]) for col in byte_cols if col in analyzer.features}
    
    # 분석 수행
    result = analyzer.predict_and_explain(sample_features)
    
    # 리포트 생성 및 출력
    report = analyzer.generate_report(
        sample_features,
        filename=ransomware_sample.get('filename', 'sample_ransomware.exe')
    )
    print(report)
    
    # 리포트 저장
    report_path = output_dir / "sample_analysis_report.txt"
    report_path.write_text(report, encoding='utf-8')
    print(f"\n✅ 리포트 저장: {report_path}")
    
    # 이상 바이트 시각화
    analyzer.visualize_anomalies(
        sample_features,
        top_k=20,
        save_path=output_dir / "sample_anomalies.png"
    )
    
    # 4. 피처 중요도 CSV 저장
    importance_csv_path = output_dir / "feature_importance.csv"
    importance_df.to_csv(importance_csv_path, index=False, encoding='utf-8-sig')
    print(f"\n✅ 피처 중요도 CSV 저장: {importance_csv_path}")
    
    # 5. 정상 파일 통계 요약
    print("\n[4] 정상 파일 통계 요약 (상위 10개 중요 피처)")
    stats_summary = []
    for _, row in importance_df.head(10).iterrows():
        stats_summary.append({
            'byte_position': row['byte_position'],
            'importance': row['importance'],
            'benign_mean': row['benign_mean'],
            'benign_std': row['benign_std']
        })
    
    stats_df = pd.DataFrame(stats_summary)
    print(stats_df)
    
    stats_csv_path = output_dir / "benign_stats_summary.csv"
    stats_df.to_csv(stats_csv_path, index=False, encoding='utf-8-sig')
    print(f"\n✅ 정상 파일 통계 요약 저장: {stats_csv_path}")
    
    print("\n" + "=" * 80)
    print("✅ 모든 분석 완료!")
    print(f"결과 저장 위치: {output_dir}")
    print("=" * 80)


if __name__ == "__main__":
    main()