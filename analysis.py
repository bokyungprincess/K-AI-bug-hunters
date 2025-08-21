# -*- coding: utf-8 -*-
"""
OWASP Top 10 정밀 분석기 (page.html + core_js/*.js)
- 입력: crawl_out/page.html, crawl_out/core_js/*.js
- 출력: crawl_out/owasp_top10_report.json
- 변경점:
  * 백엔드 유추 제거 (frontend 근거만 사용)
  * OWASP Top 10 '정확 명칭'만 사용 (카테고리명 금지)
  * '확정(Definitive) 판정'만 vulnerabilities에 포함 (검증 체크리스트 모두 통과 필수)
  * 확정 불가 항목은 excluded_candidates로 분리 (리포트 참고용)
  * 전체 offending HTML 태그는 절대 트렁케이션 금지
  * 익스플로잇/페이로드 생성 금지

필요:
  pip install beautifulsoup4 requests openai rapidfuzz tabulate

환경:
  export OPENAI_API_KEY="sk-..."
  (선택) export OPENAI_MODEL="gpt-5"
"""

import os
import re
import json
import glob
import hashlib
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from openai import OpenAI

# ---------- OpenAI ----------
OPENAI_API_KEY = ""
# ⚠️ 파일에 키를 하드코딩하지 않는 걸 권장합니다. 이미 노출된 키는 즉시 폐기/교체하세요.
if not OPENAI_API_KEY:
    raise RuntimeError("환경변수 OPENAI_API_KEY를 설정하세요.")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")

client = OpenAI(api_key=OPENAI_API_KEY)

# ---------- 가드/축약 파라미터 ----------
MAX_TOTAL_CHARS = int(os.getenv("MAX_TOTAL_CHARS", "220000"))  # user payload 직렬화 길이 가드
MAX_HTML_EVIDENCE_PER_BUCKET = int(os.getenv("MAX_HTML_EVIDENCE_PER_BUCKET", "50"))
MAX_JS_FILES = int(os.getenv("MAX_JS_FILES", "50"))
MAX_JS_EVIDENCE_PER_FILE = int(os.getenv("MAX_JS_EVIDENCE_PER_FILE", "25"))
MAX_STR_FIELD = int(os.getenv("MAX_STR_FIELD", "4000"))  # 일반 문자열 상한(원인 태그 outer_html은 제외)

# ---------- 유틸 ----------
def sha1_text(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()

def load_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def find_files(pattern: str) -> List[str]:
    return sorted(glob.glob(pattern))

def is_data_uri(u: Optional[str]) -> bool:
    return isinstance(u, str) and u.strip().lower().startswith("data:")

def abs_url(base_url: Optional[str], maybe_rel: Optional[str]) -> Optional[str]:
    if not maybe_rel:
        return None
    if is_data_uri(maybe_rel):
        return maybe_rel
    try:
        return urljoin(base_url or "", maybe_rel)
    except Exception:
        return maybe_rel

def _truncate_text(s: str, limit: int) -> str:
    if s is None:
        return ""
    if len(s) <= limit:
        return s
    head = s[: int(limit * 0.6)]
    tail = s[-int(limit * 0.3):]
    return head + "\n...\n" + tail

# ---------- HTML 증거 수집 ----------
def analyze_html(html_text: str, site_url: Optional[str]) -> Dict[str, Any]:
    soup = BeautifulSoup(html_text, "html.parser")

    def outer(el) -> str:
        try:
            return str(el)
        except Exception:
            return el.text if hasattr(el, "text") else ""

    evidence = {
        "meta": {
            "csp_meta_present": False,
            "csp_meta_tag": None,
            "charset": None,
        },
        "forms": [],
        "inline_event_handlers": [],
        "javascript_href_links": [],
        "target_blank_without_noopener": [],
        "iframes": [],
        "script_tags": [],
        "links": [],
        "potential_secrets_in_html": []
    }

    # META
    csp_meta = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "content-security-policy"})
    if csp_meta:
        evidence["meta"]["csp_meta_present"] = True
        evidence["meta"]["csp_meta_tag"] = outer(csp_meta)
    charset = soup.find("meta", attrs={"charset": True})
    if charset:
        evidence["meta"]["charset"] = outer(charset)

    # FORMS
    for form in soup.find_all("form"):
        action = form.get("action")
        method = (form.get("method") or "GET").upper()
        evidence["forms"].append({
            "outer_html": outer(form),  # 전체 태그 (생략 금지)
            "action": action,
            "action_abs": abs_url(site_url, action),
            "method": method,
        })

    # inline on* 이벤트
    for el in soup.find_all():
        for attr in list(el.attrs.keys()):
            if isinstance(attr, str) and attr.lower().startswith("on"):
                evidence["inline_event_handlers"].append({
                    "outer_html": outer(el),  # 전체 태그 (생략 금지)
                    "attr": attr,
                    "value": el.get(attr)
                })

    # javascript: 링크 & target=_blank rel 누락
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.strip().lower().startswith("javascript:"):
            evidence["javascript_href_links"].append({
                "outer_html": outer(a),
                "href": href
            })
        if (a.get("target") == "_blank") and (not a.get("rel") or "noopener" not in " ".join(a.get("rel"))):
            evidence["target_blank_without_noopener"].append({
                "outer_html": outer(a),
                "href": href,
                "href_abs": abs_url(site_url, href),
                "target": a.get("target"),
                "rel": a.get("rel")
            })
        # 일반 링크 목록(URI 후보)
        evidence["links"].append({
            "outer_html": outer(a),
            "href": href,
            "href_abs": abs_url(site_url, href)
        })

    # iframe
    for iframe in soup.find_all("iframe"):
        evidence["iframes"].append({
            "outer_html": outer(iframe),
            "src": iframe.get("src"),
            "src_abs": abs_url(site_url, iframe.get("src"))
        })

    # script 태그
    for sc in soup.find_all("script"):
        evidence["script_tags"].append({
            "outer_html": outer(sc),
            "src": sc.get("src"),
            "src_abs": abs_url(site_url, sc.get("src")),
            "integrity": sc.get("integrity"),
            "crossorigin": sc.get("crossorigin")
        })

    # 잠재적 비밀(간단 패턴)
    patterns = [
        (r"AKIA[0-9A-Z]{16}", "aws_access_key_id"),
        (r"AIzaSy[0-9A-Za-z\-_]{35}", "gcp_api_key"),
        (r"sk-[A-Za-z0-9]{20,}", "openai_key_like"),
    ]
    for regex, name in patterns:
        for m in re.finditer(regex, html_text):
            start = max(0, m.start() - 60)
            end = min(len(html_text), m.end() + 60)
            evidence["potential_secrets_in_html"].append({
                "name": name,
                "match": html_text[start:end]
            })

    return evidence

# ---------- JS 증거 수집 ----------
JS_PATTERNS = [
    (r"\beval\s*\(", "use_of_eval"),
    (r"\bnew\s+Function\s*\(", "new_Function"),
    (r"\bset(?:Timeout|Interval)\s*\(\s*(['\"])", "setTimeout_string_code"),
    (r"\.innerHTML\s*=", "innerHTML_assignment"),
    (r"\.outerHTML\s*=", "outerHTML_assignment"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML"),
    (r"\bdocument\.write\s*\(", "document_write"),
    (r"\bdocument\.cookie\b", "document_cookie_access"),
    (r"\blocalStorage\.(?:setItem|getItem|removeItem)\s*\(", "localStorage_usage"),
    (r"\bsessionStorage\.(?:setItem|getItem|removeItem)\s*\(", "sessionStorage_usage"),
    (r"\bdangerouslySetInnerHTML\b", "react_dangerouslySetInnerHTML"),
    (r"\bfetch\s*\(\s*['\"]([^'\"]+)", "fetch_call"),
    (r"\bXMLHttpRequest\s*\(", "xhr_usage"),
    (r"\.open\s*\(\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]\s*,\s*['\"]([^'\"]+)", "xhr_open"),
    (r"\bURLSearchParams\s*\(", "urlsearchparams_usage"),
    (r"\blocation\.(?:hash|search|href)\b", "location_usage"),
]

def analyze_js(js_text: str, filename: str, site_url: Optional[str]) -> Dict[str, Any]:
    lines = js_text.splitlines()
    evidences = []

    for pattern, label in JS_PATTERNS:
        for m in re.finditer(pattern, js_text, flags=re.IGNORECASE):
            line_index = js_text.count("\n", 0, m.start())
            line_no = line_index + 1
            ctx = []
            for ln in range(max(0, line_no - 1), min(len(lines), line_no + 2)):  # 앞/해당/뒤 1줄
                ctx.append({"line": ln + 1, "code": lines[ln]})
            evidences.append({
                "pattern": label,
                "regex": pattern,
                "filename": filename,
                "line_no": line_no,
                "context": ctx
            })

    endpoints = []
    for m in re.finditer(r"\bfetch\s*\(\s*['\"]([^'\"]+)", js_text):
        url = m.group(1)
        endpoints.append({"type": "fetch", "url": url, "url_abs": abs_url(site_url, url), "filename": filename})
    for m in re.finditer(r"\.open\s*\(\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]\s*,\s*['\"]([^'\"]+)", js_text, flags=re.IGNORECASE):
        method, url = m.group(1), m.group(2)
        endpoints.append({"type": "xhr", "method": method, "url": url, "url_abs": abs_url(site_url, url), "filename": filename})

    return {
        "filename": filename,
        "sha1": sha1_text(js_text),
        "evidences": evidences,
        "endpoints": endpoints
    }

def analyze_all_js(core_js_dir: str, site_url: Optional[str]) -> Dict[str, Any]:
    out = {"files": [], "summary": {"total_files": 0, "total_hits": 0}}
    files = find_files(os.path.join(core_js_dir, "*.js"))
    total_hits = 0
    for path in files:
        js_text = load_text(path)
        res = analyze_js(js_text, os.path.basename(path), site_url)
        out["files"].append(res)
        total_hits += len(res["evidences"])
    out["summary"]["total_files"] = len(files)
    out["summary"]["total_hits"] = total_hits
    return out

# ---------- 축약기 (원인 태그 outer_html은 절대 자르지 않음) ----------
def _shrink_payload(payload: dict, limit: int) -> dict:
    import copy
    cur = copy.deepcopy(payload)

    def size(obj) -> int:
        return len(json.dumps(obj, ensure_ascii=False))

    for _ in range(20):
        if size(cur) <= limit:
            break
        # JS 파일 수 제한
        js_files = cur.get("javascript", {}).get("files", [])
        if len(js_files) > MAX_JS_FILES:
            cur["javascript"]["files"] = js_files[:MAX_JS_FILES]
            continue
        # 파일별 evidences 개수 제한
        shrunk = False
        for f in cur.get("javascript", {}).get("files", []):
            if len(f.get("evidences", [])) > MAX_JS_EVIDENCE_PER_FILE:
                f["evidences"] = f["evidences"][:MAX_JS_EVIDENCE_PER_FILE]
                shrunk = True
        if shrunk:
            continue
        # HTML evidences 버킷당 개수 제한
        html_high = cur.get("html", {}).get("highlights", {})
        local_shrink = False
        for key, arr in list(html_high.items()):
            if isinstance(arr, list) and len(arr) > MAX_HTML_EVIDENCE_PER_BUCKET:
                html_high[key] = arr[:MAX_HTML_EVIDENCE_PER_BUCKET]
                local_shrink = True
        if local_shrink:
            continue

        # 긴 문자열 트렁케이션(단 outer_html은 절대 X)
        def truncate(node):
            if isinstance(node, dict):
                for k, v in list(node.items()):
                    if k == "outer_html":
                        continue
                    if isinstance(v, str):
                        if len(v) > MAX_STR_FIELD:
                            node[k] = _truncate_text(v, MAX_STR_FIELD)
                    else:
                        truncate(v)
            elif isinstance(node, list):
                for it in node:
                    truncate(it)

        truncate(cur)
    return cur

# ---------- 메시지/호출 ----------
def build_messages(site_url: Optional[str], html_ev: Dict[str, Any], js_ev: Dict[str, Any]) -> List[Dict[str, str]]:
    # 엄격 판정 규칙(프롬프트)
    system = (
        "You are an application security analyst. Analyze ONLY the provided HTML and core JavaScript evidence.\n"
        "GOAL: Report ONLY definitive OWASP Top 10 vulnerabilities that are provably exploitable based on the evidence.\n"
        "STRICT RULES:\n"
        "1) Use precise vulnerability NAMES only (e.g., 'Cross-Site Scripting (XSS)', 'Cross-Site Request Forgery (CSRF)', 'Insecure Direct Object Reference (IDOR)', 'SQL Injection', 'Server-Side Request Forgery (SSRF)', 'Server-Side Template Injection (SSTI)', 'Open Redirect', 'Clickjacking', etc.). Do NOT use category titles.\n"
        "2) Evidence MUST be frontend-verifiable: full offending HTML tags (untruncated) and JavaScript sinks/sources with exact filename+line+context.\n"
        "3) A finding goes into 'vulnerabilities' ONLY IF ALL validation checks for that class are TRUE (see 'validation' section). Otherwise, put it into 'excluded_candidates' with explicit reasons.\n"
        "4) NO payloads, NO exploit generation, NO backend inference. Do not speculate beyond the given evidence.\n"
        "5) Output STRICTLY one JSON object conforming to the schema.\n"
    )

    # 강화된 스키마
    schema = {
        "type": "object",
        "properties": {
            "site_url": {"type": ["string", "null"]},
            "summary": {
                "type": "object",
                "properties": {
                    "overall_risk": {"type": "string"},
                    "key_observations": {"type": "array", "items": {"type": "string"}},
                    "total_confirmed": {"type": "number"},
                    "total_excluded": {"type": "number"}
                },
                "required": ["overall_risk", "key_observations", "total_confirmed", "total_excluded"]
            },
            "vulnerabilities": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},  # precise vulnerability name
                        "owasp_item": {"type": "string"},  # e.g., "A03:2021-Injection"
                        "severity": {"type": "string"},     # e.g., High/Medium/Low
                        "likelihood": {"type": "string"},
                        "probability": {"type": "number"},
                        "impact": {"type": "string"},
                        "reasoning": {"type": "string"},
                        "affected_uris": {"type": "array", "items": {"type": "string"}},
                        "affected_files": {"type": "array", "items": {"type": "string"}},
                        "evidence": {
                            "type": "object",
                            "properties": {
                                "html": {"type": "array", "items": {"type": "string"}},   # FULL offending tags (no truncation)
                                "js": {"type": "array", "items": {
                                    "type": "object",
                                    "properties": {
                                        "filename": {"type": "string"},
                                        "line": {"type": "number"},
                                        "context": {"type": "array", "items": {
                                            "type": "object",
                                            "properties": {"line": {"type": "number"}, "code": {"type": "string"}},
                                            "required": ["line", "code"]
                                        }},
                                        "source": {"type": ["string", "null"]},   # e.g., location.search, innerText of user content, etc.
                                        "sink": {"type": ["string", "null"]},     # e.g., innerHTML, document.write, dangerouslySetInnerHTML
                                        "sanitization_check": {"type": ["string", "null"]},  # e.g., 'no escaping detected'
                                        "taint_flow": {"type": ["string", "null"]}  # short trace: input -> transformation -> sink
                                    },
                                    "required": ["filename", "line", "context"]
                                }}
                            },
                            "required": ["html", "js"]
                        },
                        "validation": {
                            "type": "object",
                            "properties": {
                                "class": {"type": "string"},  # e.g., "XSS", "CSRF"
                                "has_user_controlled_input": {"type": "boolean"},
                                "reaches_sensitive_sink": {"type": "boolean"},
                                "no_sanitization_or_encoding": {"type": "boolean"},
                                "is_triggerable_from_ui": {"type": "boolean"},
                                "defense_absent": {"type": "boolean"},  # e.g., CSRF token missing for state-change
                                "why_true": {"type": "string"}
                            },
                            "required": ["class", "has_user_controlled_input", "reaches_sensitive_sink",
                                         "no_sanitization_or_encoding", "is_triggerable_from_ui", "defense_absent", "why_true"]
                        },
                        "repro_steps": {"type": "array", "items": {"type": "string"}},   # high-level, no payloads
                        "remediation": {"type": "array", "items": {"type": "string"}},
                        "references": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["name", "owasp_item", "severity", "likelihood", "probability",
                                 "reasoning", "affected_uris", "evidence", "validation", "repro_steps", "remediation"]
                }
            },
            "excluded_candidates": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "hypothesis": {"type": "string"},
                        "reason": {"type": "string"},
                        "related_evidence": {"type": "object",
                            "properties": {
                                "html": {"type": "array", "items": {"type": "string"}},
                                "js": {"type": "array", "items": {
                                    "type": "object",
                                    "properties": {
                                        "filename": {"type": "string"},
                                        "line": {"type": "number"},
                                        "context": {"type": "array", "items": {
                                            "type": "object",
                                            "properties": {"line": {"type": "number"}, "code": {"type": "string"}},
                                            "required": ["line", "code"]
                                        }}
                                    },
                                    "required": ["filename", "line", "context"]
                                }}
                            }
                        }
                    },
                    "required": ["hypothesis", "reason"]
                }
            }
        },
        "required": ["summary", "vulnerabilities", "excluded_candidates"]
    }

    user_payload = {
        "site_url": site_url,
        "schema": schema,
        "html": {"highlights": html_ev},
        "javascript": js_ev,
        "instructions": {
            "no_payloads": True,
            "only_owasp_top10": True,
            "precise_names_only": True,
            "full_offending_html_required": True,
            "definitive_only": True,
            "exclude_if_any_validation_false": True
        }
    }

    user_payload_shrunk = _shrink_payload(user_payload, MAX_TOTAL_CHARS)
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user_payload_shrunk, ensure_ascii=False)}
    ]

def call_openai(messages: List[Dict[str, str]]) -> Dict[str, Any]:
    try:
        resp = client.chat.completions.create(
            model=OPENAI_MODEL,
            response_format={"type": "json_object"},
            temperature=1,  # 보수적/일관성
            messages=messages
    )
        content = resp.choices[0].message.content
        return json.loads(content)
    except Exception as e:
        print(f"[!] OpenAI 호출 실패 또는 파싱 실패: {e}")
        return {
            "summary": {
                "overall_risk": "unknown",
                "key_observations": ["OpenAI request failed or response parsing error"],
                "total_confirmed": 0,
                "total_excluded": 0
            },
            "vulnerabilities": [],
            "excluded_candidates": []
        }

# ---------- 실행 ----------
def run_owasp_top10_report(out_dir: str = "crawl_out", site_url: Optional[str] = None) -> str:
    page_path = os.path.join(out_dir, "page.html")
    core_dir = os.path.join(out_dir, "core_js")
    if not os.path.exists(page_path):
        raise FileNotFoundError(f"HTML이 없습니다: {page_path}")
    if not os.path.isdir(core_dir):
        raise FileNotFoundError(f"폴더가 없습니다: {core_dir}")

    html_text = load_text(page_path)
    html_ev = analyze_html(html_text, site_url)
    js_ev = analyze_all_js(core_dir, site_url)

    messages = build_messages(site_url, html_ev, js_ev)
    report = call_openai(messages)

    out_json = os.path.join(out_dir, "owasp_top10_report.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"[+] 분석 완료: {out_json}")
    return out_json

if __name__ == "__main__":
    url_hint = None
    urls_txt = os.path.join("crawl_out", "input_urls.txt")
    if os.path.exists(urls_txt):
        try:
            with open(urls_txt, "r", encoding="utf-8") as f:
                url_hint = f.readline().strip() or None
        except Exception as e:
            print(f"[-] URL 파일 읽기 실패: {e}")
            url_hint = None
    else:
        print(f"[-] URL 힌트 파일이 없습니다: {urls_txt}")

    run_owasp_top10_report(out_dir="crawl_out", site_url=url_hint)


# --- 자동 후처리: JSON -> PDF ---
__import__('os').system(f"{__import__('sys').executable} json_to_pdf.py")

