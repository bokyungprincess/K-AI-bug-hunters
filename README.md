# K-AI-bug-hunters
AI 기반 웹 취약점 탐지

## ✨ Key Features (요약)
- 🔎 **Crawler**: 페이지 렌더링 후 <script> 수집, 벤더 휴리스틱 + OpenAI로 core_js만 선별 저장 (page.html, core_js/*, 목록 파일 생성)
- 🧠 **analysis**: page.html + core_js/* 증거만으로 '확정' 취약점 JSON 리포트 생성 (excluded 후보 분리, 프롬프트 스키마 엄격)
- 📊 **json_to_pdf**: JSON 리포트를 한국어 단일 HTML 문서로 변환(<!doctype html> 포함, 코드 원문 보존)

> 데모 스크린샷 자리:  
> `docs/images/demo.png` (나중에 추가)

---

## 🚀Quick Start

**1) Requirements**
Python 3.10+ (권장 3.11)
Google Chrome (Selenium이 헤드리스 크롬을 사용)
인터넷 연결 (대상 사이트/모델 호출)

**2) Install**
가상환경을 추천합니다.
- macOS / Linux
python -m venv .venv && source .venv/bin/activate
- Windows (PowerShell)
python -m venv .venv; .\.venv\Scripts\Activate.ps1

-필요 패키지 설치:
pip install selenium webdriver-manager beautifulsoup4 requests openai jsbeautifier rapidfuzz tabulate

**3) Environment**
코드내 OpenAI 키 삽입

-macOS / Linux
export OPENAI_API_KEY="sk-..."           # 필수
export OPENAI_MODEL="gpt-4o-mini"        # 선택
-Windows (PowerShell)
$env:OPENAI_API_KEY="sk-..."
$env:OPENAI_MODEL="gpt-4o-mini"

**4) Run**

python crawler.py
->(프롬프트에 URL 입력)

crawler.py가 페이지를 렌더링하고 <script>를 수집합니다.

벤더 JS는 휴리스틱으로 걸러내고, 남은 후보를 OpenAI로 분류하여 core_js만 저장합니다.

크롤이 끝나면 자동으로 analysis.py(OWASP Top 10 정밀 분석)가 실행되고,
분석이 끝나면 json_to_pdf.py가 실행되어 리포트를 생성합니다.

**5) Outputs**

모든 결과물은 crawl_out/ 폴더에 생성됩니다.

crawl_out/
 ├─ page.html                     # 렌더된 최종 HTML
 ├─ core_js/                      # core_app로 분류된 JS만 저장
 ├─ core_js_list.txt              # core JS 파일명 ↔ 원본 URL
 ├─ core_js_urls.json             # core JS 요약(파일명/URL/상태/해시 등)
 ├─ owasp_top10_report.json       # 확정 취약점 분석 결과(JSON)
 └─ owasp_top10_report.pdf|html   # json_to_pdf.py 결과물 (구현에 따라 PDF 또는 HTML)

참고: 만약 analysis.py가 json_to_pdf.py를 자동 실행하지 않도록 되어 있다면,
아래처럼 수동 실행하세요.

python json_to_pdf.py

**6) Troubleshooting**

Chrome/드라이버 오류: 크롬 설치 여부 확인. 회사 PC라면 보안 정책으로 자동 설치가 막힐 수 있습니다.

LLM 호출 에러: OPENAI_API_KEY 설정 확인, 네트워크 프록시/방화벽 점검.

토큰/길이 초과: 페이지가 매우 크면 분석 입력 축약 로직이 동작합니다. 그래도 실패한다면 대상 페이지 범위를 줄이세요.






