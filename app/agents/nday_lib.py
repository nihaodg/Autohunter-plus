"""N-day 打法库：指纹 → 已知漏洞检测链的运行时注入。

数据源 app/data_static/nday_tactics.json（独立 JSON 直查，不写 Intel 表——
record_intel 对 payload 值有 300 字符硬截断，检测请求体必坏；且 _dedup_hash
对 fingerprint 类只用 tactic 字段，会与运行时沉淀条目撞唯一索引）。

设计原则：
- 只读检测/无害验证性质（每条 harmless_note 必填，红线审计位）
- 加载/匹配/渲染全 try/except 降级：库出问题绝不能挂掉 worker
- 限量注入防 prompt 膨胀（块 1800 字符、每指纹 2 条、总数 6 条）
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_DATA_FILE = Path(__file__).resolve().parent.parent / "data_static" / "nday_tactics.json"

# 块级字数上限（与 intel.py 的 _MAX_INJECT_CHARS 同量级，防 prompt 膨胀）
_MAX_INJECT_CHARS = int(os.environ.get("NDAY_MAX_INJECT_CHARS", "1800"))
# 每指纹最多注入条数 / 总条数上限（多指纹目标防膨胀）
_MAX_PER_FP = 2
_MAX_TOTAL = 6
# 匹配阶段每指纹上限（渲染前粗筛，给渲染层留排序空间）
_MATCH_PER_FP = 4

_INDEX: dict[str, list[dict]] | None = None
_FALLBACK_TITLE: list[tuple[str, dict]] = []


def load_nday_index() -> dict[str, list[dict]]:
    """加载 N-day 打法索引 {fingerprint: [条目]}（模块级缓存，失败返回空 dict）。

    条目合法性校验：缺关键字段或缺 harmless_note（红线审计位）的条目直接丢弃。
    """
    global _INDEX, _FALLBACK_TITLE
    if _INDEX is not None:
        return _INDEX
    _INDEX = {}
    try:
        raw = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
        entries = raw.get("entries") if isinstance(raw, dict) else raw
        if not isinstance(entries, list):
            return _INDEX
        for item in entries:
            if not isinstance(item, dict):
                continue
            fp = str(item.get("fingerprint") or "").strip()
            name = str(item.get("name") or "").strip()
            check = item.get("check") if isinstance(item.get("check"), dict) else None
            harmless = str(item.get("harmless_note") or "").strip()
            # 红线硬门槛：没有无害性说明的打法不允许注入
            if not (fp and name and check and check.get("path") and harmless):
                continue
            _INDEX.setdefault(fp, []).append(item)
            for kw in item.get("fallback_title_kw") or []:
                kw = str(kw).strip().lower()
                if kw:
                    _FALLBACK_TITLE.append((kw, item))
        # 高危优先
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for items in _INDEX.values():
            items.sort(key=lambda e: sev_order.get(str(e.get("severity_hint", "")).lower(), 9))
    except Exception:
        _INDEX = {}
        _FALLBACK_TITLE = []
    return _INDEX


def _dedupe(entries: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for e in entries:
        eid = str(e.get("id") or id(e))
        if eid in seen:
            continue
        seen.add(eid)
        out.append(e)
    return out


def match_nday_by_fingerprint(fingerprints: list[str]) -> list[dict]:
    """按系统指纹取打法条目（每指纹最多 _MATCH_PER_FP 条，全局去重）。"""
    try:
        index = load_nday_index()
        out: list[dict] = []
        for fp in fingerprints or []:
            if not fp:
                continue
            out.extend(index.get(fp, [])[:_MATCH_PER_FP])
        return _dedupe(out)
    except Exception:
        return []


def match_nday_by_title_server(title: str, server: str = "") -> list[dict]:
    """指纹未命中时的兜底：按 title/server 关键词匹配（如 body/UA 没识别出的系统）。"""
    try:
        load_nday_index()  # 确保 _FALLBACK_TITLE 已建
        blob = f"{title or ''} {server or ''}".lower()
        if not blob:
            return []
        out: list[dict] = []
        seen: set[str] = set()
        for kw, item in _FALLBACK_TITLE:
            if kw in blob:
                eid = str(item.get("id") or id(item))
                if eid not in seen:
                    seen.add(eid)
                    out.append(item)
        return out
    except Exception:
        return []


def render_nday_block(entries: list[dict]) -> str:
    """渲染成注入 worker 的 prompt 块：可照抄的 http_request 调用 + 命中特征 + 打穿引导。

    二次限量（每指纹 2 条 / 总数 6 条）+ 块字数硬上限。空列表返回空串（零开销）。
    """
    try:
        if not entries:
            return ""
        # 二次限量：按指纹分组各取 2 条，总数 6 条
        by_fp: dict[str, list[dict]] = {}
        for e in entries:
            by_fp.setdefault(str(e.get("fingerprint") or "unknown"), []).append(e)
        picked: list[dict] = []
        for fp_items in by_fp.values():
            picked.extend(fp_items[:_MAX_PER_FP])
        picked = picked[:_MAX_TOTAL]
        if not picked:
            return ""

        lines = [
            "# N-day 检测库命中（已识别系统指纹，优先验证）",
            "以下检测请求可直接照抄执行（仅替换主机名），每条 1-2 轮；全部未命中再走常规挖掘。",
            "",
        ]
        for i, e in enumerate(picked, 1):
            check = e.get("check") or {}
            method = str(check.get("method") or "GET").upper()
            path = str(check.get("path") or "/")
            headers = check.get("headers") if isinstance(check.get("headers"), dict) else {}
            body = str(check.get("body") or "")
            match = e.get("match") if isinstance(e.get("match"), dict) else {}
            status_in = match.get("status_in") or []
            contains_all = match.get("body_contains_all") or []
            name = str(e.get("name") or "")
            sev = str(e.get("severity_hint") or "").upper()
            hparts = ", ".join(f'"{k}": "{v}"' for k, v in headers.items())
            call = (
                f'http_request(url="http://<目标>{path}", method="{method}"'
                + (f", headers={{{hparts}}}" if hparts else "")
                + (f', data="""{body}"""' if body else "")
                + ")"
            )
            lines.append(f"## {i}. [{sev}] {name}")
            lines.append(f"  {call}")
            msig = []
            if status_in:
                msig.append(f"状态 {status_in}")
            if contains_all:
                msig.append(f"body 含 {' 且 '.join(str(c) for c in contains_all)}")
            if match.get("body_len_gt"):
                msig.append(f"body 长度 > {match['body_len_gt']}")
            if msig:
                lines.append(f"  命中特征：{'，'.join(msig)}")
            nxt = str(e.get("next") or "").strip()
            if nxt:
                lines.append(f"  命中后：{nxt}")
            harmless = str(e.get("harmless_note") or "").strip()
            if harmless:
                lines.append(f"  （无害性：{harmless}）")
            lines.append("")
        block = "\n".join(lines)
        if len(block) > _MAX_INJECT_CHARS:
            block = block[:_MAX_INJECT_CHARS] + "\n…(其余检测已截断)"
        return block + "\n\n"
    except Exception:
        return ""
