# -*- coding: utf-8 -*-
"""
json_to_html_llm.py
- Input : crawl_out/owasp_top10_report.json
- Action: LLM이 한국어로 보기 좋은 HTML 보고서를 직접 작성 (간단 나열 형식)
- Output: crawl_out/owasp_top10_report.html
Notes:
- 중간 Markdown/PDF 없음. 완전한 단일 HTML만 생성.
- 아래 HARDCODED_OPENAI_API_KEY에 키를 넣거나, 환경변수 OPENAI_API_KEY로 설정.
"""

import os, json, datetime
from pathlib import Path

# ========================
# 🔑 API KEY / MODEL 설정
# ========================
HARDCODED_OPENAI_API_KEY = ""   # 예: "sk-..." (비우면 환경변수 OPENAI_API_KEY 사용)
HARDCODED_OPENAI_MODEL   = "gpt-5"  # 비우면 환경변수 OPENAI_MODEL 또는 "gpt-5"

OPENAI_API_KEY = HARDCODED_OPENAI_API_KEY or os.getenv("OPENAI_API_KEY")
OPENAI_MODEL   = HARDCODED_OPENAI_MODEL or os.getenv("OPENAI_MODEL", "gpt-5")

def load_json(p: Path):
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)

def call_llm_to_html(report: dict) -> str:
    """
    LLM에게 완전한 HTML 문서를 생성하도록 요청.
    출력은 각 취약점을 아래 4항목으로 나열:
      - 취약점 이름 (종류)
      - 취약점 등급 및 실현 가능성
      - 취약점이 터진 코드 (생략 없이)
      - 취약점 설명
    """
    if not OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY가 필요합니다. HARDCODED 또는 환경변수로 설정하세요.")

    from openai import OpenAI
    client = OpenAI(api_key=OPENAI_API_KEY)

    system = (
        "역할: 당신은 AppSec 리포트 에디터입니다. 주어진 OWASP 분석 JSON만 근거로, "
        "발견된 모든 '확정 취약점'을 한국어로 간결하게 나열한 HTML 보고서를 작성하십시오.\n"
        "출력 형식(엄수): 완전한 단일 HTML 문서(<!doctype html>부터 </html>까지), <meta charset='utf-8'> 포함, 외부 리소스 불가.\n"
        "각 취약점은 아래 네 블록을 순서대로 포함하는 <section class='vuln'>로 출력:\n"
        "1) <h2>취약점 이름 (종류)</h2> : JSON의 name, owasp_item 등에서 이름/종류를 병기 (예: Cross-Site Scripting (XSS), A03:2021-Injection)\n"
        "2) <h3>취약점 등급 및 실현 가능성</h3> : severity, likelihood, probability(있으면 %)를 한국어로 자연스럽게 기술\n"
        "3) <h3>취약점이 터진 코드 (생략 없이)</h3> : JSON evidence에 포함된 HTML 태그 전체, JS 컨텍스트(파일/라인/코드)를 <pre><code>로 '원문 그대로' 모두 나열 (절대 줄임표/생략 금지)\n"
        "4) <h3>취약점 설명</h3> : JSON의 reasoning/impact/validation(왜 참인지)/repro_steps(고수준)/remediation(권고)을 모아 한국어 서술. 페이로드/익스플로잇 생성 금지.\n"
        "주의사항:\n"
        "- JSON에 없는 내용은 절대 만들지 마십시오. 백엔드 추측 금지. 민감정보 출력 금지.\n"
        "- 파일명/라인/URI 등은 원본과 일치시켜야 합니다.\n"
        "- excluded_candidates(제외 후보)가 있다면 별도 섹션 <section class='excluded'>로 '왜 제외됐는지' 간단히 나열하되, 코드 원문이 있으면 동일하게 <pre><code>로 제공합니다.\n"
        "- 표지/요약/개선계획 같은 일반 섹션은 넣지 말고, 요구된 형식으로 취약점 나열만 하십시오.\n"
    )

    user = {
        "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "report_json": report
    }

    resp = client.chat.completions.create(
        model=OPENAI_MODEL,
        response_format={"type": "text"},   # 일부 모델은 temperature 비지원 → 아예 미지정
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user, ensure_ascii=False)}
        ],
    )
    html_doc = resp.choices[0].message.content.strip()

    # 최소 검증: 완전한 HTML 문서 여부
    doc_lower = html_doc.lower()
    if "<html" not in doc_lower or "</html>" not in doc_lower:
        raise RuntimeError("LLM이 완전한 HTML 문서를 반환하지 않았습니다.")
    if "<meta charset" not in doc_lower:
        # 안전을 위해 meta charset 주입
        html_doc = html_doc.replace("<head>", "<head><meta charset='utf-8'>")

    return html_doc

def main():
    crawl = Path("crawl_out")
    in_json = crawl / "owasp_top10_report.json"
    out_html = crawl / "owasp_top10_report.html"

    if not in_json.exists():
        raise FileNotFoundError(f"입력 JSON을 찾을 수 없습니다: {in_json.resolve()}")

    report = load_json(in_json)
    html_doc = call_llm_to_html(report)

    # 간단 스타일 주입(가독성)
    style = """
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
             margin: 40px; line-height: 1.6; }
      h1 { margin-top: 0; }
      section.vuln, section.excluded { border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px 18px; margin-bottom: 18px; }
      section.vuln h2 { margin: 0 0 8px; font-size: 20px; }
      section.vuln h3, section.excluded h3 { margin: 12px 0 6px; font-size: 16px; }
      pre { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 10px; overflow-x: auto; }
      code { white-space: pre-wrap; word-break: break-word; }
      .muted { color: #6b7280; font-size: 12px; }
    </style>
    """
    # <head>에 스타일이 없다면 삽입
    if "<style" not in html_doc.lower():
        html_doc = html_doc.replace("<head>", "<head>" + style)

    crawl.mkdir(parents=True, exist_ok=True)
    out_html.write_text(html_doc, encoding="utf-8")
    print(f"[+] HTML 보고서 생성: {out_html}")

if __name__ == "__main__":
    main()



