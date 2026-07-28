# aegis-scanner
# 🛡️ Project AEGIS (아이기스 스미싱 탐지기)

**안전한 디지털 환경을 위한 가상 환경 기반 의심 링크 분석 및 샌드박스 채증 도구**

👉 **[앱 바로가기 클릭!] (https://aegis-scanner-239.streamlit.app/)**

## 🔍 주요 기능
1. **IoC(침해지표) 기반 URL 분석:** 단축 URL, IP 직접 접속, 피싱 키워드 등 구조적 위험도를 즉시 판별합니다.
2. **격리된 샌드박스 채증:** 의심스러운 링크를 사용자의 기기가 아닌 가상의 헤드리스 브라우저(Headless Browser)에서 실행하여 안전하게 화면을 캡처합니다.
3. **사용자 친화적 경고:** 전문적인 보안 용어 대신 알기 쉬운 비유를 통해 일반인의 스미싱 피해를 예방합니다.

## 🛠️ 사용 기술
* Python, Streamlit, Selenium Webdriver, URL parsing 정규표현식
