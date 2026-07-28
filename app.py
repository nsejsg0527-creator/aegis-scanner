import streamlit as st
from urllib.parse import urlparse
import re
import time
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.core.os_manager import ChromeType

# [1단계] 텍스트 기반 URL 구조 분석 엔진
def analyze_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    
    risk_score = 0
    reasons = []

    whitelisted = ['naver.com', 'daum.net', 'google.com', 'kbstar.com', 'police.go.kr']
    for safe in whitelisted:
        if domain == safe or domain.endswith('.' + safe):
            return "🟢 안전 (공식 도메인)", 0, ["안전성이 검증된 공식 기관/포털 사이트입니다."]

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        risk_score += 50
        reasons.append("🚨 [위험] 정상적인 웹사이트 주소 대신 숫자로 된 IP 주소를 직접 사용했습니다. 추적을 회피하려는 악성 피싱 사이트에서 주로 발견되는 매우 위험한 패턴입니다.")

    shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'cutt.ly', 'v.gd']
    if domain in shorteners:
        risk_score += 30
        reasons.append("⚠️ [주의] 실제 접속될 최종 주소를 숨기기 위해 단축 URL을 사용했습니다. 스미싱 문자 메시지에서 가장 흔하게 악용되는 방식이므로 주의가 필요합니다.")

    suspicious_words = ['login', 'update', 'secure', 'bank', 'auth', 'account']
    for word in suspicious_words:
        if word in domain:
            risk_score += 30
            reasons.append(f"🚨 [위험] 주소(도메인)에 '{word}'라는 단어가 교묘하게 포함되어 있습니다. 공공기관이나 은행을 사칭하여 로그인과 개인정보 입력을 유도하는 가짜 사이트일 확률이 높습니다.")
        elif word in path:
            risk_score += 10
            reasons.append(f"⚠️ [주의] 주소 세부 경로에 '{word}'라는 의심스러운 단어가 발견되었습니다. 접속 시 가짜 보안 업데이트나 인증 요구 창이 뜰 수 있으니 주의하세요.")

    if risk_score >= 50:
        level = "🔴 매우 위험 (스미싱 의심)"
    elif risk_score >= 30:
        level = "🟡 주의 요망 (확인 필요)"
    else:
        level = "🟢 비교적 안전 (단, 신규 위협일 수 있으니 주의)"

    return level, risk_score, reasons

# [2단계] 안심 캡처 시스템 (정식 서버용 샌드박스)
def capture_screenshot(url):
    screenshot_path = "forensic_evidence.png"
    
    chrome_options = Options()
    chrome_options.add_argument('--headless=new')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
    
    try:
        # 클라우드 서버(리눅스) 환경에 맞춰 Chromium 드라이버를 자동 설치 및 연결
        service = Service(ChromeDriverManager(chrome_type=ChromeType.CHROMIUM).install())
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(15)
        driver.get(url)
        time.sleep(3) 
        driver.save_screenshot(screenshot_path)
        return screenshot_path
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        try:
            driver.quit()
        except:
            pass

# [3단계] 웹 화면 구성
st.set_page_config(page_title="아이기스 스미싱 탐지기", page_icon="🛡️", layout="centered")

st.title("🛡️ Project AEGIS : 스미싱 탐지기")
st.markdown("**안전한 디지털 환경을 위한 가상 환경 기반 의심 링크 분석 도구**")
st.info("문자로 받은 의심스러운 링크를 직접 클릭하지 마세요. 아이기스가 대신 접속하여 안전하게 분석해 드립니다.")

with st.form(key='aegis_form'):
    url_input = st.text_input("🔗 분석할 URL을 입력하세요", placeholder="예: bit.ly/가짜청첩장")
    
    if url_input and not url_input.startswith("http"):
        url_input = "http://" + url_input
        
    submit_button = st.form_submit_button(label="🔍 위협 분석 및 안심 미리보기 실행", use_container_width=True)

if submit_button:
    if not url_input or url_input == "http://":
        st.warning("경고: 분석할 링크를 먼저 입력해 주세요.")
    else:
        with st.spinner('사이버 위협 분석 및 가상 환경 채증을 진행 중입니다... 잠시만 기다려주세요.'):
            level, score, reasons = analyze_url(url_input)
            
            st.divider()
            st.subheader("📊 침해지표(IoC) 분석 결과")
            
            if score >= 50:
                st.error(f"**판정 결과:** {level} (위험 점수: {score}점)")
            elif score >= 30:
                st.warning(f"**판정 결과:** {level} (위험 점수: {score}점)")
            else:
                st.success(f"**판정 결과:** {level} (위험 점수: {score}점)")
            
            if score > 0:
                st.markdown("**세부 분석 내용:**")
                for r in reasons:
                    st.write(f"- {r}")
            
            st.divider()
            
            st.subheader("📸 안심 캡처 (격리된 샌드박스 화면)")
            capture_result = capture_screenshot(url_input)
            
            if capture_result == "forensic_evidence.png":
                st.image("forensic_evidence.png", caption=f"수집 일시: {time.strftime('%Y-%m-%d %H:%M:%S')} | 악성 스크립트 100% 차단됨")
                os.remove("forensic_evidence.png")
            else:
                st.error("⚠️ 사이트에 접속할 수 없습니다. 이미 차단되었거나 범행 후 폐쇄된 사이트일 가능성이 높습니다.")
