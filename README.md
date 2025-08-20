# K-AI-bug-hunters
AI 기반 웹 취약점 탐지

## ✨ Key Features (요약)
- 🔎 **Crawler**: 하위 URL주소 수집, HTML/JS 추출
- 🧠 **AI Assistant**: HTML/JS 기반 취약점 제시, 공격 페이로드 제시
- 📊 **Report**: 공격 페이로드 제시 보고서 작성

> 데모 스크린샷 자리:  
> `docs/images/demo.png` (나중에 추가)

---

## 🧭 Table of Contents
- [Quick Start]
- [Configuration]
- [Usage]
- [Project Layout]
- [Roadmap]
- [Tech Stack]
- [Acknownledgements]
  
---

## 🚀 Quick Start
# ex)Python >= 3.11

python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp env.example .env

# ex)Dev server (예: FastAPI)
uvicorn app.main:app --reload  # 또는 python app.py

## ⚙️Configuration
# Target / Crawl
START_URL=(http://192.168.51.22:3000/#/)
CRAWL_MAX_DEPTH=2
CRAWL_CONCURRENCY=5

# AI
OPENAI_API_KEY=<your-key>
MODEL_NAME=gpt-<…>

# Report
REPORT_DIR=reports

## 🧪 Usage
# 단일 URL 스캔
python -m app scan --url https://target.tld --modules xss,sqli --out reports/scan.html

# 리스트 입력
python -m app scan --list targets.txt --headless --screenshot

## 🗂Project Layout
├─ app/ or src/
│  ├─ crawler/        # 하위주소 HTML, JS 추출, 렌더링(Selenium)
│  ├─ payloads/       # XSS/SQLi/… 페이로드 데이터
│  ├─ reporters/      # HTML/CSV/JSON 리포트 생성
│  └─ main.py         # CLI/웹 서버 엔트리
├─ tests/             # 단위/통합 테스트
├─ package.json
├─ env.example
├─ docs/              # 아키텍처/스크린샷/설계 메모
└─ reports/           # 출력물(ignored)

## 🗺 Roadmap
 크롤러를 통해 하위주소의 HTML/JS 추출

 LLM을 이용한 취약점 분석

 payload데이터로 학습시킨 LLM을 이용해 최적 payload 추천받음

 LLM을 통해 보고서 요약/심각도 평가

## 🧰 Tech Stack
Language: <Python 3.11 / Node 18>

Web: <FastAPI / Express>

Headless: <Playwright / Selenium>

DB (옵션): <SQLite / MongoDB>

Lint/Test: <ruff/pytest> or <eslint/jest>

## 🙏 Acknowledgments

<참고한 오픈소스/데이터/문서 링크>

<팀원/멘토 크레딧>





