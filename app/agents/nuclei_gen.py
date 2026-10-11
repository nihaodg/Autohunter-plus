"""通杀 PoC → nuclei 模板生成与安全校验。

Killsweep 实打验证成功后，把已确认的 PoC 编译成 nuclei YAML 模板落盘，
供 collector/prefilter 阶段对指纹匹配目标零成本复跑（mini-runner，不引入 nuclei 二进制）。

安全设计（红线：不爆破/不改密/不写操作）：
- validate_template 黑名单校验：硬编码域名拒绝（防打到范围外）、写操作词拒绝、
  方法白名单、matchers 必须非空（防"发了就算中"）
- 校验不过不落盘，宁枉勿纵
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - pyyaml 缺失时功能整体降级关闭
    yaml = None

# 模板落盘根目录（Docker 内 /app/data，volume ah_data；本地开发按 DB_PATH 同级推导）
_TEMPLATE_ROOT = Path(
    __import__("os").environ.get("NUCLEI_TEMPLATE_ROOT", "data/nuclei_templates")
)

# 方法白名单：只允许只读/探测类
_METHOD_ALLOW = {"GET", "POST", "OPTIONS"}
# 写操作/破坏性词黑名单（词边界匹配 body/path）
_DANGEROUS_RE = re.compile(
    r"""\b(delete|drop|truncate|insert|update|shutdown|reboot|passwd|reset|mkfs|rm\s+-rf|exec|eval|system\()\b""",
    re.I,
)
# 硬编码目标检测：path/host 不允许出现具体域名/IP（必须用 {{BaseURL}}）
_HARDCODED_HOST_RE = re.compile(r"https?://(?!\{\{BaseURL\}\})[a-z0-9.\-]+\.[a-z]{2,}", re.I)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_BODY_MAX = 2000


def safe_slug(product_key: str, vuln_type: str) -> str:
    """生成安全的模板 id/文件名 slug。"""
    raw = f"{product_key or 'unknown'}-{vuln_type or 'vuln'}".lower()
    slug = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    return (slug or "autohunter-template")[:120]


_GEN_SYSTEM_PROMPT = """你是 nuclei 模板生成器。输入是一个【已人工/AI 复核验证】的漏洞 PoC（原始请求/响应或 curl 命令）。
你的唯一任务：把它转写成一份 nuclei YAML 模板，用于后续对该产品其它部署的自动化检测。

# 硬性安全规则（违反即废弃）
1. path 必须以 {{BaseURL}} 开头——禁止出现任何硬编码域名/IP（模板会被批量跑在其它资产上）。
2. method 只允许 GET/POST/OPTIONS——禁止任何写操作/破坏性 payload（DELETE/DROP/UPDATE/INSERT/shutdown/改密等）。
3. 必须有 matchers 且至少能区分"存在漏洞"与"正常响应"（状态码或 body 特征），禁止"发了就算命中"。
4. body ≤ 2000 字符；只保留检测所需的最小 payload。
5. 不允许 interactsh/oob 反连（离线检测优先状态码/响应特征）。

# 输出格式
直接输出 YAML（不要 markdown 代码块包裹、不要解释）：
id: <产品-漏洞类型-slug>
info:
  name: <漏洞名>
  severity: <high|medium|low>
  description: <一句话>
  x-autohunter-vuln-type: <原始 vuln_type>
http:
  - method: <GET|POST>
    path:
      - "{{BaseURL}}<路径>"
    <headers/body 按需>
    matchers:
      - type: status
        status: [200]   # 或 type: word / words: [...]"""


async def generate_template(
    llm: Any,
    poc: str,
    raw_request: str,
    product_key: str,
    vuln_type: str,
    notes: str = "",
) -> str:
    """单次 LLM 调用生成模板 YAML（异步版）。失败/空返回空串，绝不抛异常。"""
    import asyncio
    return await asyncio.to_thread(
        generate_template_sync, llm, poc, raw_request, product_key, vuln_type, notes
    )


def generate_template_sync(
    llm: Any,
    poc: str,
    raw_request: str,
    product_key: str,
    vuln_type: str,
    notes: str = "",
) -> str:
    """同步版：llm.chat 是阻塞调用，供线程池执行。失败返回空串，绝不抛异常。"""
    try:
        user = (
            f"# 产品指纹\n{product_key or 'unknown'}\n\n"
            f"# 漏洞类型\n{vuln_type or 'unknown'}\n\n"
            f"# PoC（curl 或描述）\n{poc[:2500]}\n\n"
            f"# 原始请求包\n{raw_request[:2500]}\n\n"
            f"# 通杀分析备注\n{notes[:800]}\n\n"
            "按系统提示的安全规则生成 nuclei YAML，直接输出 YAML 本体。"
        )
        result = llm.chat(
            messages=[{"role": "system", "content": _GEN_SYSTEM_PROMPT},
                      {"role": "user", "content": user}],
            temperature=0.0,
        )
        text = ""
        if isinstance(result, dict):
            text = str(result.get("content") or result.get("text") or "")
        elif isinstance(result, str):
            text = result
        elif result is not None and hasattr(result, "content"):
            text = str(getattr(result, "content") or "")
        # 剥掉可能的 markdown 包裹
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
            text = re.sub(r"\n?```\s*$", "", text)
        ok, reason = validate_template(text)
        if not ok:
            return ""
        return text
    except Exception:
        return ""


def validate_template(yaml_text: str) -> tuple[bool, str]:
    """静态校验 LLM 生成的 nuclei 模板。返回 (ok, reason)。不联网、不执行。"""
    if yaml is None:
        return False, "pyyaml 未安装，模板校验不可用"
    if not yaml_text or not yaml_text.strip():
        return False, "空模板"
    if len(yaml_text) > 20_000:
        return False, "模板过大"
    try:
        doc = yaml.safe_load(yaml_text)
    except Exception as e:
        return False, f"YAML 解析失败: {type(e).__name__}"
    if not isinstance(doc, dict):
        return False, "模板根必须是映射"

    tid = str(doc.get("id") or "").strip()
    if not tid or not re.fullmatch(r"[a-z0-9][a-z0-9\-_.]{2,120}", tid.lower()):
        return False, f"id 非法: {tid!r}"

    info = doc.get("info")
    if not isinstance(info, dict) or not str(info.get("name") or "").strip():
        return False, "缺 info.name"
    if not str(info.get("severity") or "").strip():
        return False, "缺 info.severity"

    http = doc.get("http")
    if not isinstance(http, list) or not http:
        return False, "缺 http 块"

    for i, block in enumerate(http):
        if not isinstance(block, dict):
            return False, f"http[{i}] 非映射"
        method = str(block.get("method") or "GET").upper()
        if method not in _METHOD_ALLOW:
            return False, f"http[{i}] 方法不允许: {method}"
        paths = block.get("path")
        if not paths or not isinstance(paths, list):
            return False, f"http[{i}] 缺 path"
        for p in paths:
            p = str(p)
            if "{{BaseURL}}" not in p:
                return False, f"http[{i}] path 未用 {{{{BaseURL}}}}: {p[:80]}"
            if _HARDCODED_HOST_RE.search(p) or _IP_RE.search(p):
                return False, f"http[{i}] path 疑似硬编码目标: {p[:80]}"
            if _DANGEROUS_RE.search(p):
                return False, f"http[{i}] path 含写操作词: {p[:80]}"
        body = str(block.get("body") or "")
        if len(body) > _BODY_MAX:
            return False, f"http[{i}] body 超长"
        if body and _DANGEROUS_RE.search(body):
            return False, f"http[{i}] body 含写操作词"
        if not block.get("matchers"):
            return False, f"http[{i}] 缺 matchers"
    return True, "ok"


def _template_root() -> Path:
    root = Path(_TEMPLATE_ROOT)
    if not root.is_absolute():
        # Docker 内 DB_PATH=/app/data/autohunter.db → 取 /app/data；本地取 cwd/data
        import os
        db_path = os.environ.get("DB_PATH", "")
        if db_path:
            root = Path(db_path).resolve().parent / "nuclei_templates"
        else:
            root = Path("data") / "nuclei_templates"
    return root


def save_template(task_id: str, product_key: str, vuln_type: str, yaml_text: str) -> Path | None:
    """校验通过后落盘 <root>/<task_id>/<slug>.yaml。校验失败返回 None。"""
    ok, reason = validate_template(yaml_text)
    if not ok:
        return None
    try:
        d = _template_root() / str(task_id or "misc")
        d.mkdir(parents=True, exist_ok=True)
        f = d / f"{safe_slug(product_key, vuln_type)}.yaml"
        f.write_text(yaml_text, encoding="utf-8")
        return f
    except Exception:
        return None


# ---------------------------------------------------------------------------
# mini-runner：只解释自家生成模板用到的子集
#（单 path、GET/POST、{{BaseURL}} 替换、status/contains matcher）。
# 复杂 DSL（word-and 条件组合、multi-request、interactsh 等）跳过不跑——
# 只会漏跑不会误报。
# ---------------------------------------------------------------------------

def load_sweep_templates() -> list[dict]:
    """扫描模板目录，加载可被 mini-runner 执行的模板。返回 [{id, doc}]。"""
    out: list[dict] = []
    if yaml is None:
        return out
    try:
        root = _template_root()
        if not root.is_dir():
            return out
        for f in sorted(root.rglob("*.yaml"))[:50]:  # 硬顶 50 个，防目录膨胀
            try:
                doc = yaml.safe_load(f.read_text(encoding="utf-8"))
                if not isinstance(doc, dict):
                    continue
                ok, _ = validate_template(f.read_text(encoding="utf-8"))
                if ok:
                    out.append({"id": str(doc.get("id")), "doc": doc})
            except Exception:
                continue
    except Exception:
        pass
    return out


def _match_hit(matchers: list, status: int, body: str) -> bool:
    """极简 matcher 求值：只支持 status / contains（默认任意一个命中即 true，对齐 nuclei word/or 语义）。"""
    try:
        has_and = False  # 是否存在 and 条件 matcher（and 组必须全命中）
        or_hit = False   # or 组任一命中
        for m in matchers or []:
            if not isinstance(m, dict):
                continue
            mtype = str(m.get("type") or "").lower()
            condition = str(m.get("condition") or "or").lower()
            if mtype == "status":
                codes = m.get("status") or []
                if isinstance(codes, (int, str)):
                    codes = [codes]
                hit = status in [int(c) for c in codes if str(c).isdigit()]
            elif mtype in ("word", "contains"):
                words = m.get("words") or ([m.get("part")] if m.get("part") else [])
                hit = any(str(w) in body for w in words if w)
            else:
                continue  # 不认识的 matcher 类型：跳过（宁漏勿误）
            if condition == "and":
                has_and = True
                if not hit:
                    return False
            elif hit:
                or_hit = True
        if has_and and or_hit:
            return True  # nuclei 语义：and 组全命中，与 or 组任一命中可叠加
        if has_and:
            return True  # 只有 and 组且全部通过
        return or_hit
    except Exception:
        return False


def run_template_sweep(
    base_url: str,
    fingerprints: list[str],
    title: str = "",
) -> list[dict]:
    """对单目标跑模板子集。返回命中列表 [{template_id, status_code, evidence}]。

    每目标最多 5 个模板、每模板 1 次请求、整体由调用方控制超时。
    """
    import httpx

    out: list[dict] = []
    templates = load_sweep_templates()
    if not templates or not base_url:
        return out
    base = base_url.rstrip("/")
    if not base.startswith(("http://", "https://")):
        return out
    client = None
    try:
        client = httpx.Client(verify=False, timeout=6.0, follow_redirects=False)
        for t in templates[:5]:
            try:
                doc = t["doc"]
                http = doc.get("http") or []
                if not http or not isinstance(http[0], dict):
                    continue
                blk = http[0]
                paths = blk.get("path") or []
                if not paths or "{{BaseURL}}" not in str(paths[0]):
                    continue
                if len(paths) > 1 or len(http) > 1:
                    continue  # multi-request 子集外，跳过
                url = str(paths[0]).replace("{{BaseURL}}", base)
                method = str(blk.get("method") or "GET").upper()
                resp = client.request(method, url,
                                      content=str(blk.get("body") or "") or None)
                body = resp.text[:20_000]
                if _match_hit(blk.get("matchers") or [], resp.status_code, body):
                    out.append({
                        "template_id": t["id"],
                        "status_code": resp.status_code,
                        "evidence": body[:300],
                    })
                if len(out) >= 3:  # 单目标命中上限：3 条足够进 reviewer 流程
                    break
            except Exception:
                continue
    except Exception:
        pass
    finally:
        try:
            if client:
                client.close()
        except Exception:
            pass
    return out
