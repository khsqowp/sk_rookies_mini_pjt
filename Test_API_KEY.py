"""
OpenAI API 키 테스트 및 사용 가능한 GPT 모델 확인
"""

import os
import openai
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

def test_openai_api():
    """OpenAI API 키와 사용 가능한 모델을 테스트합니다."""

    api_key = os.getenv("OPENAI_API_KEY")

    if not api_key:
        print("❌ OPENAI_API_KEY가 설정되지 않았습니다.")
        print("   .env 파일에 OPENAI_API_KEY=your-key-here 를 추가하세요.")
        return None

    print(f"✅ API 키 발견: {api_key[:20]}..." + "*" * 20)
    print()

    try:
        client = openai.OpenAI(api_key=api_key)

        # GPT-4 시리즈 모델 목록 (우선순위 순)
        gpt4_models = [
            "gpt-4o",                    # GPT-4 Omni (최신, 가장 강력)
            "gpt-4o-2024-11-20",         # GPT-4 Omni (2024년 11월)
            "gpt-4o-2024-08-06",         # GPT-4 Omni (2024년 8월)
            "gpt-4o-2024-05-13",         # GPT-4 Omni (2024년 5월)
            "gpt-4o-mini",               # GPT-4 Omni Mini (빠르고 저렴)
            "gpt-4o-mini-2024-07-18",    # GPT-4 Omni Mini (2024년 7월)
            "gpt-4-turbo",               # GPT-4 Turbo (최신)
            "gpt-4-turbo-2024-04-09",    # GPT-4 Turbo (2024년 4월)
            "gpt-4-turbo-preview",       # GPT-4 Turbo Preview
            "gpt-4-0125-preview",        # GPT-4 (2024년 1월)
            "gpt-4-1106-preview",        # GPT-4 (2023년 11월)
            "gpt-4",                     # GPT-4 (기본)
            "gpt-4-0613",                # GPT-4 (2023년 6월)
            "gpt-3.5-turbo",             # GPT-3.5 Turbo (폴백)
            "gpt-3.5-turbo-0125",        # GPT-3.5 Turbo (2024년 1월)
        ]

        print("=" * 80)
        print("GPT-4 시리즈 모델 테스트 시작")
        print("=" * 80)
        print()

        available_models = []

        for model_name in gpt4_models:
            print(f"🔍 테스트 중: {model_name}...", end=" ")

            try:
                # 간단한 테스트 요청
                response = client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": "You are a helpful assistant."},
                        {"role": "user", "content": "Say 'OK' if you can read this."}
                    ],
                    max_tokens=10,
                    temperature=0
                )

                result = response.choices[0].message.content.strip()
                print(f"✅ 사용 가능 (응답: {result})")
                available_models.append(model_name)

            except openai.NotFoundError as e:
                print(f"❌ 접근 불가 (404 - 모델을 찾을 수 없음)")
            except openai.PermissionDeniedError as e:
                print(f"❌ 권한 없음 (403 - 프로젝트에서 접근 불가)")
            except Exception as e:
                print(f"❌ 오류: {type(e).__name__} - {str(e)[:50]}")

        print()
        print("=" * 80)
        print("테스트 결과 요약")
        print("=" * 80)
        print()

        if available_models:
            print(f"✅ 사용 가능한 모델: {len(available_models)}개")
            print()
            print("우선순위 순:")
            for i, model in enumerate(available_models, 1):
                print(f"  {i}. {model}")
            print()

            # 최적 모델 선택
            best_model = available_models[0]
            print("=" * 80)
            print(f"🎯 권장 모델: {best_model}")
            print("=" * 80)
            print()

            # 성능 비교 정보
            print("📊 모델 특성:")
            if "gpt-4o" in best_model:
                print("   - GPT-4 Omni: 최신 멀티모달 모델, 빠르고 강력")
                print("   - 비용: 중간")
                print("   - 속도: 매우 빠름")
            elif "gpt-4-turbo" in best_model:
                print("   - GPT-4 Turbo: 빠른 응답, 긴 컨텍스트")
                print("   - 비용: 중간")
                print("   - 속도: 빠름")
            elif "gpt-4" in best_model:
                print("   - GPT-4: 가장 강력한 추론 능력")
                print("   - 비용: 높음")
                print("   - 속도: 보통")
            elif "gpt-3.5" in best_model:
                print("   - GPT-3.5 Turbo: 빠르고 저렴")
                print("   - 비용: 낮음")
                print("   - 속도: 매우 빠름")
            print()

            return best_model
        else:
            print("❌ 사용 가능한 GPT 모델이 없습니다.")
            print()
            print("💡 해결 방법:")
            print("   1. API 키가 유효한지 확인하세요")
            print("   2. OpenAI 계정에 결제 수단이 등록되어 있는지 확인하세요")
            print("   3. 프로젝트 설정에서 모델 접근 권한을 확인하세요")
            print("   4. https://platform.openai.com/account/limits 에서 한도를 확인하세요")
            print()
            return None

    except Exception as e:
        print(f"❌ API 연결 오류: {e}")
        return None

if __name__ == "__main__":
    print()
    print("=" * 80)
    print("OpenAI API 키 및 GPT 모델 테스트")
    print("=" * 80)
    print()

    best_model = test_openai_api()

    if best_model:
        print()
        print("=" * 80)
        print("다음 단계")
        print("=" * 80)
        print()
        print(f"Test_Dashboard.py에서 모델을 '{best_model}'로 변경합니다.")
        print()
