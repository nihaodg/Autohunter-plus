"""Hunter (鹰图) 资产搜索服务 —— 集成自用户的 hunter1 工具集。

复用原有踩坑结论：
- Hunter 的 WAF 会通过 TLS 指纹拦截 Python httpx/requests/urllib（403），
  所以 API 请求必须走 curl 子进程（http_client.py 的方案）。
- 多 Key 自动轮换：配额耗尽/401/429 自动切下一个（hunter_keys.yaml）。

用途：给前端「Hunter 搜索」页提供后端 API —— 查询资产 → 去重 → 一键复制 URL，
再粘贴到任务创建页的手动目标清单。纯只读测绘，不碰目标。
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode, urlparse

# curl 可执行文件（Windows 优先 curl.exe）
_CURL_BIN = shutil.which("curl.exe") or shutil.which("curl") or "curl"
_BASE_URL = os.environ.get("HUNTER_BASE_URL", "https://hunter.qianxin.com").rstrip("/")
# hunter_keys.yaml 查找顺序：环境变量指定 → 项目 data/ → 用户工具原位置（本地开发）
_KEY_FILES = [
    Path(os.environ.get("HUNTER_KEYS_YAML", "")),
    Path("data/hunter_keys.yaml"),
    Path("D:/app/VulnResearch/AI漏洞挖掘/hunter1/hunter_keys.yaml"),
]

_LOCK = threading.Lock()
_CFG_CACHE: dict | None = None
_CFG_CACHE_AT: float = 0.0
_CFG_TTL = 30.0  # 配置缓存 30s（key 配额状态在 userInfo 查询后落盘，短暂缓存可接受）

try:
    import yaml as _yaml
except ImportError:  # pragma: no cover
    _yaml = None


# ---------------------------------------------------------------------------
# 配置加载（hunter_keys.yaml：keys + defaults + output）
# ---------------------------------------------------------------------------

def _find_key_file() -> Optional[Path]:
    for p in _KEY_FILES:
        try:
            if p and p.is_file():
                return p
        except Exception:
            continue
    return None


def load_cfg(force: bool = False) -> dict:
    """读取 hunter_keys.yaml（缓存 30s）。结构：{keys:[{key,name,enabled}], defaults:{...}, output:{...}}"""
    global _CFG_CACHE, _CFG_CACHE_AT
    now = time.time()
    if not force and _CFG_CACHE is not None and now - _CFG_CACHE_AT < _CFG_TTL:
        return _CFG_CACHE
    cfg: dict = {"keys": [], "defaults": {"page_size": 20, "is_web": 3, "days_back": 7},
                 "output": {"fields": "ip,port,domain,url,web_title,status_code,company"}}
    try:
        f = _find_key_file()
        if f and _yaml is not None:
            data = _yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            if isinstance(data.get("keys"), list):
                cfg["keys"] = [k for k in data["keys"] if isinstance(k, dict) and k.get("key")]
            if isinstance(data.get("defaults"), dict):
                cfg["defaults"].update({k: v for k, v in data["defaults"].items() if v is not None})
            if isinstance(data.get("output"), dict):
                cfg["output"].update(data["output"])
    except Exception:
        pass
    with _LOCK:
        _CFG_CACHE = cfg
        _CFG_CACHE_AT = now
    return cfg


def enabled_keys() -> list[dict]:
    return [k for k in load_cfg().get("keys", []) if k.get("enabled", True)]


# ---------------------------------------------------------------------------
# curl 子进程 HTTP（绕 Hunter WAF 的 TLS 指纹拦截）
# ---------------------------------------------------------------------------

def _curl_get_json(url: str, timeout: int = 30) -> Optional[dict]:
    try:
        result = subprocess.run(
            [_CURL_BIN, "-k", "-s", "--max-time", str(timeout), "--connect-timeout", "10", url],
            capture_output=True, timeout=timeout + 5, text=True, encoding="utf-8", errors="replace",
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except Exception:
        return None


def _api_get(path: str, params: dict, timeout: int = 30) -> Optional[dict]:
    return _curl_get_json(f"{_BASE_URL}{path}?{urlencode(params)}", timeout)


# ---------------------------------------------------------------------------
# 多 Key 轮换搜索（配额耗尽/401/429 自动切下一个）
# ---------------------------------------------------------------------------

def hunter_search(
    query: str,
    page: int = 1,
    page_size: int | None = None,
    is_web: int | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    fields: str | None = None,
) -> dict:
    """执行一次 Hunter 搜索，返回 API 原始响应（含 code/data/message）。

    所有 key 失败时返回 {"code": 0, "message": "所有 Hunter Key 均不可用"}。
    """
    cfg = load_cfg()
    keys = enabled_keys()
    if not keys:
        return {"code": 0, "message": "未找到可用的 Hunter Key（检查 hunter_keys.yaml 配置）"}

    defaults = cfg.get("defaults", {})
    page_size = int(page_size or defaults.get("page_size", 20))
    is_web = int(is_web if is_web is not None else defaults.get("is_web", 3))
    end_time = end_time or datetime.now().strftime("%Y-%m-%d")
    start_time = start_time or (datetime.now() - timedelta(days=int(defaults.get("days_back", 7)))).strftime("%Y-%m-%d")
    fields = fields if fields is not None else cfg.get("output", {}).get("fields", "")

    encoded = base64.urlsafe_b64encode((query or "").encode("utf-8")).decode("ascii")
    base_params = {
        "search": encoded, "page": str(page), "page_size": str(page_size),
        "is_web": str(is_web), "start_time": start_time, "end_time": end_time,
    }
    if fields:
        base_params["fields"] = fields

    disabled: set[str] = set()
    last: Optional[dict] = None
    for i in range(len(keys)):
        avail = [k for k in keys if k.get("name") not in disabled]
        if not avail:
            break
        ki = avail[i % len(avail)]
        params = {**base_params, "api-key": ki["key"]}
        data = _api_get("/openApi/search", params)
        if data is None:
            disabled.add(ki.get("name", ""))
            continue
        code = data.get("code")
        if code == 200:
            rest = str(data.get("data", {}).get("rest_quota", ""))
            if "剩余积分：0" in rest or rest.strip() == "0":
                disabled.add(ki.get("name", ""))
                continue
            return data
        if code in (401, 429):
            disabled.add(ki.get("name", ""))
            last = data
            continue
        return data  # 400 语法错误等：直接透传给前端
    return last or {"code": 0, "message": "所有 Hunter Key 均不可用"}


def hunter_keys_status() -> list[dict]:
    """查询各 key 的配额状态（调 /openApi/userInfo）。"""
    out = []
    for k in load_cfg().get("keys", []):
        name = k.get("name", "unknown")
        key = k.get("key", "")
        row: dict = {"name": name, "enabled": bool(k.get("enabled", True)), "rest_quota": "-", "status": "未检测"}
        if k.get("enabled", True):
            try:
                data = _api_get("/openApi/userInfo", {"api-key": key}, timeout=15)
                if data and data.get("code") == 200:
                    d = data.get("data", {})
                    row["rest_quota"] = d.get("rest_quota", "-")
                    row["status"] = "可用"
                elif data and data.get("code") in (401, 403):
                    row["status"] = "认证失败"
                else:
                    row["status"] = "查询失败"
            except Exception:
                row["status"] = "查询异常"
        else:
            row["status"] = "已禁用"
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# 结果提取去重（对齐 extract_urls.py 的逻辑）
# ---------------------------------------------------------------------------

def _host_from_url(url: str) -> str:
    try:
        u = url if "://" in url else "http://" + url
        return (urlparse(u).hostname or "").lower().lstrip(".")
    except Exception:
        return ""


def extract_assets(arr: list[dict], mode: str = "url") -> dict:
    """从 Hunter 结果 arr 提取去重资产。

    mode: url=完整URL（优先 url 字段，回退 domain，再回退 ip:port）
          host=主机名（优先 domain，回退从 url 提取）
    返回 {items: [{value, domain, ip, port, title, company, status_code}], total_raw, total_unique}
    """
    seen: set[str] = set()
    items: list[dict] = []
    for it in arr or []:
        if not isinstance(it, dict):
            continue
        domain = (it.get("domain") or "").strip().lower().lstrip(".")
        url = (it.get("url") or "").strip()
        if mode == "host":
            val = domain or _host_from_url(url)
            if not val:
                continue
        else:
            if url:
                val = url
            elif domain:
                val = f"http://{domain}"
            else:
                ip = (it.get("ip") or "").strip()
                port = it.get("port") or ""
                if not ip:
                    continue
                val = f"http://{ip}:{port}" if port else f"http://{ip}"
        key = val.lower().rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        items.append({
            "value": val,
            "domain": domain,
            "ip": it.get("ip", ""),
            "port": str(it.get("port", "") or ""),
            "title": (it.get("web_title") or it.get("title") or "")[:120],
            "company": (it.get("company") or it.get("company_name") or "")[:80],
            "status_code": it.get("status_code", ""),
        })
    return {"items": items, "total_raw": len(arr or []), "total_unique": len(items)}
