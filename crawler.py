# -*- coding: utf-8 -*-
"""
HTML + Core JS 전용 크롤러
- URL 로딩 → <script> 수집 (외부/인라인은 분류에만 사용)
- 명백한 벤더 JS는 휴리스틱으로 제외
- 나머지는 OpenAI로 core_app/vendor/unknown 분류
- 결과물: page.html + core_js/*.js (+ core_js_urls.json / core_js_list.txt)
- 전체 JS 풀백업(js_all) 저장하지 않음

필수:
  pip install selenium webdriver-manager beautifulsoup4 requests openai jsbeautifier
환경:
  export OPENAI_API_KEY="sk-..."
  (선택) export OPENAI_MODEL="gpt-4o-mini"
"""

import os
import re
import json
import time
import hashlib
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# ---------- OpenAI ----------
from openai import OpenAI

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
if not OPENAI_API_KEY:
    raise RuntimeError("환경변수 OPENAI_API_KEY를 설정하세요.")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")

client = OpenAI(api_key=OPENAI_API_KEY)

# ---------- Optional: JS pretty-print ----------
try:
    import jsbeautifier
    BEAUTIFY = True
    _opts = jsbeautifier.default_options()
    _opts.indent_size = 2
    _opts.end_with_newline = True
    _opts.preserve_newlines = True
    _opts.max_preserve_newlines = 2
    _opts.brace_style = "collapse"
except Exception:
    BEAUTIFY = False
    _opts = None

@dataclass
class JsAsset:
    url: str
    final_url: str
    filename: str
    size_bytes: Optional[int] = None
    code_sample_head: str = ""
    code_sample_tail: str = ""
    inline: bool = False
    inline_index: Optional[int] = None
    http_status: Optional[int] = None
    sha1: Optional[str] = None

UA = {"User-Agent": "Mozilla/5.0"}

def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()

def _abs_url(base: str, src: str) -> str:
    return urljoin(base, src)

def _guess_filename(u: str, inline=False, idx=None) -> str:
    if inline:
        return f"inline_{idx or 0}.js"
    p = urlparse(u)
    name = os.path.basename(p.path) or "script.js"
    name = name.split("?")[0].split("#")[0] or "script.js"
    return name

def _is_probably_vendor(name_or_url: str) -> bool:
    s = (name_or_url or "").lower()
    vendor_hits = [
        # 라이브러리/프레임워크/유틸
        "jquery", "lodash", "underscore", "moment", "dayjs",
        "bootstrap", "popper", "tailwind", "uikit", "semantic", "antd",
        "swiper", "slick", "hammer", "gsap", "anime",
        "chart", "chart.min", "chartjs", "d3.", "three.",
        "datatables", "select2", "fullcalendar", "fancybox", "lightbox",
        "react", "react-dom", "preact", "vue", "angular", "svelte",
        # 분석/태그/광고
        "gtag", "googletagmanager", "analytics", "adsbygoogle",
        "hotjar", "mixpanel", "clarity", "matomo", "tagmanager",
        # 경로 힌트
        "/vendor/", "/vendors/", "/lib/", "/libs/", "/plugin/", "/plugins/", "/cdn/",
        # 일반적으로 벤더가 .min.js 배포
        ".min.js",
    ]
    exceptions = [
        # 앱 번들도 minify될 수 있으므로 일부 예외
        "app.min.js", "bundle.min.js", "main.min.js", "index.min.js",
        "/static/js/main.", "/static/js/app.", "/assets/js/app.", "/dist/app."
    ]
    cdn_domains = [
        "unpkg.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
        "ajax.googleapis.com", "staticfile.org", "yastatic.net",
        "lib.baomitu.com", "cloudflare", "bootcdn", "googleapis"
    ]
    if any(d in s for d in cdn_domains):
        return True
    if any(v in s for v in vendor_hits) and not any(e in s for e in exceptions):
        return True
    if re.search(r"(vendor|vendors)(~|\.|/)", s):
        return True
    return False

def _sample_code(text: str, head_chars: int = 1200, tail_chars: int = 800) -> (str, str):
    text = text or ""
    head = text[:head_chars]
    tail = text[-tail_chars:] if len(text) > tail_chars else ""
    return head, tail

def _http_get_text(u: str, timeout: int = 15) -> (Optional[str], Optional[int]):
    try:
        r = requests.get(u, timeout=timeout, headers=UA)
        r.encoding = r.encoding or "utf-8"
        return (r.text, r.status_code)
    except Exception:
        return (None, None)

def crawl_scripts(url: str, out_dir: str = "crawl_out") -> List[JsAsset]:
    """
    페이지에서 <script> 모두 수집 (외부 JS는 내용을 읽어 샘플만 보유)
    HTML은 page.html로 저장.
    JS는 여기서는 저장하지 않음. (core만 나중에 저장)
    """
    os.makedirs(out_dir, exist_ok=True)

    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")

    driver = webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=chrome_options
    )

    assets: List[JsAsset] = []
    try:
        print(f"[+] 페이지 로딩: {url}")
        driver.get(url)
        time.sleep(2.5)

        html = driver.page_source
        soup = BeautifulSoup(html, "html.parser")
        (os.path.join(out_dir, "page.html") and open(os.path.join(out_dir, "page.html"), "w", encoding="utf-8")).write(soup.prettify())

        scripts = soup.find_all("script")
        inline_count = 0
        seen_urls = set()

        for sc in scripts:
            src = sc.get("src")
            if src:
                absu = _abs_url(url, src)
                if absu in seen_urls:
                    continue
                seen_urls.add(absu)

                filename = _guess_filename(absu)
                code, status = _http_get_text(absu)
                head, tail = _sample_code(code or "")

                assets.append(JsAsset(
                    url=src,
                    final_url=absu,
                    filename=filename,
                    inline=False,
                    http_status=status,
                    size_bytes=len((code or "").encode("utf-8", errors="ignore")),
                    code_sample_head=head,
                    code_sample_tail=tail,
                    sha1=_sha1(code or "")
                ))
            else:
                code = sc.string or sc.get_text() or ""
                if not code.strip():
                    continue
                inline_count += 1
                head, tail = _sample_code(code)
                assets.append(JsAsset(
                    url="(inline)",
                    final_url=url,
                    filename=_guess_filename("", inline=True, idx=inline_count),
                    inline=True,
                    inline_index=inline_count,
                    http_status=200,
                    size_bytes=len(code.encode("utf-8", errors="ignore")),
                    code_sample_head=head,
                    code_sample_tail=tail,
                    sha1=_sha1(code)
                ))

        print(f"[+] 스크립트 수집: 외부 {len([a for a in assets if not a.inline])}개, 인라인 {len([a for a in assets if a.inline])}개")
        return assets

    finally:
        driver.quit()

def classify_core_js_with_ai(assets: List[JsAsset], page_url: str) -> List[Dict[str, Any]]:
    """
    명백한 벤더는 휴리스틱으로 제외, 나머지는 LLM에 core/vendor/unknown 분류 요청
    """
    pre = []
    to_ai = []
    for a in assets:
        if a.inline:
            # 기본적으로 인라인은 제외 (필요 시 옵션으로 포함 가능)
            continue
        if _is_probably_vendor(a.filename) or _is_probably_vendor(a.final_url):
            pre.append({
                "filename": a.filename, "final_url": a.final_url,
                "label": "vendor", "confidence": 0.99, "reason": "vendor_heuristic"
            })
        else:
            to_ai.append(a)

    if not to_ai:
        return pre

    def brief(a: JsAsset) -> Dict[str, Any]:
        return {
            "filename": a.filename,
            "final_url": a.final_url,
            "size_bytes": a.size_bytes,
            "http_status": a.http_status,
            "head_sample": a.code_sample_head,
            "tail_sample": a.code_sample_tail,
        }

    payload = [brief(a) for a in to_ai]

    system_msg = (
        "You are a strict web app JavaScript auditor. "
        "Goal: identify only 'core_app' assets (business logic, routing, state/store, API calls, controllers, view composition). "
        "Classify each asset as 'core_app' or 'vendor' or 'unknown'. Prefer 'vendor' for known libs, charts, ui kits, analytics, utils. "
        "Return compact JSON only."
    )
    user_msg = {
        "task": "Classify JS assets to find true app logic only",
        "page_url": page_url,
        "assets": payload,
        "output_format": {
            "type": "object",
            "properties": {
                "classified": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "filename": {"type": "string"},
                            "final_url": {"type": "string"},
                            "label": {"type": "string", "enum": ["core_app", "vendor", "unknown"]},
                            "confidence": {"type": "number"},
                            "reason": {"type": "string"}
                        },
                        "required": ["filename", "final_url", "label"]
                    }
                }
            },
            "required": ["classified"]
        }
    }

    resp = client.chat.completions.create(
        model=OPENAI_MODEL,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system_msg},
            {"role": "user", "content": json.dumps(user_msg, ensure_ascii=False)}
        ],
        temperature=1
    )

    content = resp.choices[0].message.content
    try:
        data = json.loads(content)
        ai_classified = data.get("classified", [])
    except Exception:
        ai_classified = [{
            "filename": a.filename, "final_url": a.final_url,
            "label": "unknown", "confidence": 0.0, "reason": "parse_error"
        } for a in to_ai]

    return pre + ai_classified

def _beautify_js_if_possible(code: str) -> str:
    if BEAUTIFY:
        try:
            return jsbeautifier.beautify(code, _opts)
        except Exception:
            return code
    return code

def download_core_js_only(assets: List[JsAsset],
                          classified: List[Dict[str, Any]],
                          out_dir: str = "crawl_out") -> Dict[str, Any]:
    """
    분류 결과에서 core_app만 다시 받아 저장 (HTML은 이미 저장됨)
    """
    by_key = {(a.final_url, a.filename): a for a in assets}
    core_dir = os.path.join(out_dir, "core_js")
    os.makedirs(core_dir, exist_ok=True)

    core_list: List[Dict[str, Any]] = []

    for item in classified:
        if item.get("label") != "core_app":
            continue

        key = (item.get("final_url", ""), item.get("filename", ""))
        a = by_key.get(key)
        if not a:
            # filename만 매칭 시도
            cand = [x for x in assets if (not x.inline) and x.filename == item.get("filename")]
            a = cand[0] if cand else None
        if not a:
            continue

        code, status = _http_get_text(a.final_url)
        if not code:
            continue

        # 포맷팅(선택)
        code_out = _beautify_js_if_possible(code)

        # 저장 파일명 충돌 회피
        dst = os.path.join(core_dir, a.filename or "core.js")
        base, ext = os.path.splitext(dst)
        i = 1
        while os.path.exists(dst):
            dst = f"{base}_{i}{ext or '.js'}"
            i += 1

        with open(dst, "w", encoding="utf-8", errors="ignore") as f:
            f.write(code_out)

        core_list.append({
            "filename": os.path.basename(dst),
            "source_url": a.final_url,
            "status": status,
            "size_bytes": len(code.encode("utf-8", errors="ignore")),
            "sha1": _sha1(code)
        })

    # 리스트 저장
    list_txt = os.path.join(out_dir, "core_js_list.txt")
    list_json = os.path.join(out_dir, "core_js_urls.json")
    with open(list_txt, "w", encoding="utf-8") as f:
        for r in core_list:
            f.write(f"{r['filename']}\t{r['source_url']}\n")
    with open(list_json, "w", encoding="utf-8") as f:
        json.dump(core_list, f, ensure_ascii=False, indent=2)

    print(f"[+] 핵심 JS {len(core_list)}개 저장 완료")
    print(f"[+] 리스트 파일: {list_txt}")
    print(f"[+] URL JSON:   {list_json}")

    return {"core_js": core_list, "list_txt": list_txt, "list_json": list_json}

def run_core_only(url: str, out_dir: str = "crawl_out") -> Dict[str, Any]:
    os.makedirs(out_dir, exist_ok=True)
    assets = crawl_scripts(url, out_dir=out_dir)
    classified = classify_core_js_with_ai(assets, page_url=url)
    result = download_core_js_only(assets, classified, out_dir=out_dir)

    print("\n=== CORE JS (AI 선정) ===")
    for item in result["core_js"]:
        print(f"- {item['source_url']}")
    print(f"\n[완료] 결과 폴더: {out_dir} (page.html + core_js/)")
    return result

if __name__ == "__main__":
    target = input("크롤링할 URL을 입력하세요: ").strip()
    if not target:
        print("[-] URL이 비었습니다. 종료합니다.")
    else:
        # --- URL txt 파일 저장 ---
        urls_txt_path = os.path.join("crawl_out", "input_urls.txt")
        os.makedirs("crawl_out", exist_ok=True)
        with open(urls_txt_path, "w", encoding="utf-8") as f:
            f.write(target + "\n")
        print(f"[+] 입력 URL 저장 완료: {urls_txt_path}")

        # --- 크롤링 실행 ---
        run_core_only(target)

        # --- 크롤링 완료 후 analysis.py 실행 ---
        print("\n[+] 분석 단계 시작: analysis.py 실행")
        try:
            subprocess.run([sys.executable, "analysis.py"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] analysis.py 실행 실패: {e}")


