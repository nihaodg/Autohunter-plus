"""Hunter 资产搜索 API —— 给前端「Hunter 搜索」页用。

只读测绘：查询 Hunter（鹰图）→ 去重 → 前端一键复制 URL → 粘到任务创建页。
Key 从 hunter_keys.yaml 读取（多 key 自动轮换），请求走 curl 子进程绕 WAF。
"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app import hunter_service

router = APIRouter(prefix="/api/hunter", tags=["hunter"])

# curl 子进程是阻塞 IO：丢线程池执行，不卡事件循环
_IO_EXECUTOR = asyncio.Semaphore(4)


@router.get("/status")
async def keys_status():
    """各 Hunter Key 的配额状态。"""
    loop = asyncio.get_running_loop()
    rows = await loop.run_in_executor(None, hunter_service.hunter_keys_status)
    cfg = hunter_service.load_cfg()
    return {
        "keys": rows,
        "key_count": len(hunter_service.enabled_keys()),
        "defaults": cfg.get("defaults", {}),
    }


@router.get("/search")
async def search(
    query: str = Query(..., min_length=1, max_length=500, description="Hunter 查询语法"),
    page: int = Query(1, ge=1, le=100),
    page_size: int = Query(20, ge=1, le=100),
    is_web: int = Query(3, ge=1, le=3),
    mode: str = Query("url", pattern="^(url|host)$"),
    start_time: str = Query("", pattern=r"^\d{4}-\d{2}-\d{2}$"),
    end_time: str = Query("", pattern=r"^\d{4}-\d{2}-\d{2}$"),
):
    """执行 Hunter 搜索并返回去重后的资产列表。"""
    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(
        None,
        lambda: hunter_service.hunter_search(
            query=query, page=page, page_size=page_size, is_web=is_web,
            start_time=start_time or None, end_time=end_time or None,
        ),
    )
    if data.get("code") != 200:
        raise HTTPException(502, f"Hunter 查询失败: {data.get('message') or f'code={data.get('code')}'}")
    payload = data.get("data") or {}
    extracted = hunter_service.extract_assets(payload.get("arr") or [], mode=mode)
    return {
        "total": int(payload.get("total") or 0),
        "rest_quota": payload.get("rest_quota", ""),
        "page": page,
        "page_size": page_size,
        **extracted,
    }


class CopyPayload(BaseModel):
    values: list[str]


@router.post("/copy-text")
async def copy_text(payload: CopyPayload):
    """把勾选的资产合成一段可复制的纯文本（每行一个，可直接粘进手动目标清单）。"""
    values = [v.strip() for v in (payload.values or []) if v and v.strip()]
    if not values:
        raise HTTPException(400, "values 不能为空")
    if len(values) > 500:
        raise HTTPException(400, "单次最多 500 条")
    return {"text": "\n".join(values), "count": len(values)}
