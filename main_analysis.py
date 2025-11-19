# main_analysis.py
"""
랜섬웨어 탐지 시스템 통합 실행 스크립트
- 다중 모델 학습 및 비교
- 헤더 바이트 분석
- 벡터 DB 통합
"""
import sys
from pathlib import Path
import json
import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np

from config import MODEL_PATH, FEATURES_PATH


def print_header(title: str):
    """섹션 헤더 출력"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def run_model_training():
    """다중 모델 학습 실행"""
    print_header("1. 다중 모델 학습 및 성능 비교")
    
    try:
        from train_model import main as train_main
        train_main()
        return True
    except Exception as e:
        print(f"❌ 모델 학습 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_header_analysis():
    """헤더 바이트 분석 실행"""
    print_header("2. PE 헤더 바이트 중요도 및 이상값 분석")
    
    try:
        from header_analysis import main as analysis_main
        analysis_main()
        return True
    except Exception as e:
        print(f"❌ 헤더 분석 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_vector_db_integration():
    """벡터 DB 통합 실행"""
    print_header("3. Faiss 벡터 DB 통합 및 유사 샘플 검색")
    
    try:
        # Faiss는 별도의 서버 없이 동작하므로 바로 실행
        from vectordb_integration import main as vector_main
        vector_main()
        return True
    except Exception as e:
        print(f"⚠️  벡터 DB 통합 실패: {e}")
        import traceback
        traceback.print_exc()
        return False


def generate_final_report():
    """최종 종합 리포트 생성"""
    print_header("4. 최종 종합 리포트")
    
    try:
        # 모델 비교 결과 로딩
        comparison_path = MODEL_PATH.parent / "model_comparison.json"
        if not comparison_path.exists():
            print("⚠️  모델 비교 결과 파일이 없습니다.")
            return
        
        comparison = json.loads(comparison_path.read_text(encoding="utf-8"))
        
        print("\n[모델 성능 비교 요약]")
        print("-" * 80)
        
        models = comparison['models']
        metrics = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
        
        # 테이블 헤더
        print(f"{'모델':<20}", end="")
        for metric in metrics:
            print(f"{metric.upper():<12}", end="")
        print()
        print("-" * 80)
        
        # 각 모델의 성능
        for model_name, scores in models.items():
            print(f"{model_name:<20}", end="")
            for metric in metrics:
                value = scores.get(metric, 0)
                print(f"{value:<12.4f}", end="")
            print()
        
        print("-" * 80)
        print(f"\n🏆 최고 성능 모델: {comparison['best_model']}")
        print(f"   F1 Score: {models[comparison['best_model']]['f1']:.4f}")
        
        # 데이터셋 정보
        print("\n[데이터셋 정보]")
        print("-" * 80)
        dataset_info = comparison['dataset_info']
        print(f"총 샘플 수: {dataset_info['total_samples']}")
        print(f"  - 정상: {dataset_info['benign']}")
        print(f"  - 랜섬웨어: {dataset_info['ransomware']}")
        print(f"\n학습 데이터: {dataset_info['train_size']}")
        print(f"검증 데이터: {dataset_info['val_size']}")
        print(f"테스트 데이터: {dataset_info['test_size']}")
        print(f"\n선택된 피처 수: {comparison['feature_count']}")
        
        # 피처 중요도 요약
        importance_csv = MODEL_PATH.parent / "analysis_results" / "feature_importance.csv"
        if importance_csv.exists():
            print("\n[중요 헤더 바이트 TOP 10]")
            print("-" * 80)
            df = pd.read_csv(importance_csv)
            print(df.head(10).to_string(index=False))
        
        # 최종 리포트 저장
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("랜섬웨어 탐지 시스템 최종 분석 리포트")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        report_lines.append("[1] 모델 성능 비교")
        report_lines.append("-" * 80)
        for model_name, scores in models.items():
            report_lines.append(f"\n{model_name}:")
            for metric, value in scores.items():
                report_lines.append(f"  - {metric}: {value:.4f}")
        
        report_lines.append(f"\n최고 성능 모델: {comparison['best_model']}")
        
        report_lines.append("\n\n[2] 데이터셋 정보")
        report_lines.append("-" * 80)
        report_lines.append(f"총 샘플 수: {dataset_info['total_samples']}")
        report_lines.append(f"정상: {dataset_info['benign']}, 랜섬웨어: {dataset_info['ransomware']}")
        
        report_lines.append("\n\n[3] 주요 발견사항")
        report_lines.append("-" * 80)
        report_lines.append("• PE 헤더의 특정 바이트 위치가 랜섬웨어 판별에 중요한 역할을 함")
        report_lines.append("• 정상 파일 대비 이상값을 보이는 헤더 바이트를 통해 랜섬웨어 탐지 가능")
        report_lines.append(f"• {comparison['feature_count']}개의 선택된 피처로 높은 정확도 달성")
        
        report_path = MODEL_PATH.parent / "final_report.txt"
        report_path.write_text("\n".join(report_lines), encoding='utf-8')
        print(f"\n✅ 최종 리포트 저장: {report_path}")
        
    except Exception as e:
        print(f"❌ 리포트 생성 실패: {e}")
        import traceback
        traceback.print_exc()


def print_usage():
    """사용법 출력"""
    print("\n사용법:")
    print("  python main_analysis.py [옵션]")
    print("\n옵션:")
    print("  all        - 전체 파이프라인 실행 (기본값)")
    print("  train      - 모델 학습만 실행")
    print("  analyze    - 헤더 분석만 실행")
    print("  vector     - 벡터 DB 통합만 실행")
    print("  report     - 최종 리포트만 생성")
    print("\n예시:")
    print("  python main_analysis.py")
    print("  python main_analysis.py train")
    print("  python main_analysis.py analyze")


def main():
    """메인 실행 함수"""
    
    print_header("랜섬웨어 탐지 시스템 - 통합 분석 파이프라인")
    
    # 명령행 인자 처리
    mode = "all"
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
    
    if mode not in ["all", "train", "analyze", "vector", "report"]:
        print(f"❌ 알 수 없는 옵션: {mode}")
        print_usage()
        return
    
    print(f"\n실행 모드: {mode.upper()}")
    
    # 단계별 실행
    success = True
    
    if mode in ["all", "train"]:
        if not run_model_training():
            success = False
            if mode == "train":
                return
    
    if mode in ["all", "analyze"]:
        if not run_header_analysis():
            success = False
            if mode == "analyze":
                return
    
    if mode in ["all", "vector"]:
        run_vector_db_integration()  # 실패해도 계속 진행
    
    if mode in ["all", "report"]:
        generate_final_report()
    
    # 최종 메시지
    print("\n" + "=" * 80)
    if success:
        print("✅ 모든 분석이 성공적으로 완료되었습니다!")
    else:
        print("⚠️  일부 단계에서 오류가 발생했습니다.")
    print("=" * 80)
    
    # 결과 파일 위치 안내
    print("\n[생성된 파일 위치]")
    output_dir = MODEL_PATH.parent
    print(f"• 모델 파일: {output_dir}")
    print(f"• 분석 결과: {output_dir / 'analysis_results'}")
    print(f"• 최종 리포트: {output_dir / 'final_report.txt'}")
    print(f"• 모델 비교: {output_dir / 'model_comparison.json'}")
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()