"""N-day 打法库（nday_lib）单测：加载/匹配/限量/渲染。"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from app.agents import nday_lib


# ---------- 真实数据文件加载 ----------

def test_load_real_index_not_empty():
    """真实 nday_tactics.json 必须能加载且每条都有 harmless_note（红线门槛）。"""
    index = nday_lib.load_nday_index()
    assert index, "nday_tactics.json 加载结果为空"
    total = 0
    for fp, items in index.items():
        assert isinstance(fp, str) and fp
        for e in items:
            assert e.get("harmless_note"), f"{e.get('id')} 缺 harmless_note"
            assert str(e["check"]["path"]).startswith("/"), f"{e.get('id')} path 不以 / 开头"
            total += 1
    assert total >= 10, "首发条目数异常偏少"


def test_load_is_cached():
    """二次调用返回同一缓存对象（模块级缓存）。"""
    assert nday_lib.load_nday_index() is nday_lib.load_nday_index()


# ---------- 指纹匹配 ----------

def test_match_by_fingerprint_hits_and_dedup():
    entries = nday_lib.match_nday_by_fingerprint(["oa_tongda"])
    assert entries, "oa_tongda 应命中打法"
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids)), "存在重复条目"
    # 每指纹限量
    for e in entries:
        assert e["fingerprint"] == "oa_tongda"


def test_match_by_fingerprint_per_fp_limit():
    """每指纹匹配上限 _MATCH_PER_FP=4。"""
    many = nday_lib.match_nday_by_fingerprint(["oa_tongda", "mw_druid", "framework_springboot"])
    assert len(many) <= nday_lib._MATCH_PER_FP * 3


def test_match_empty_or_unknown_fp():
    assert nday_lib.match_nday_by_fingerprint([]) == []
    assert nday_lib.match_nday_by_fingerprint(["no_such_fp"]) == []


# ---------- 标题兜底匹配 ----------

def test_match_by_title_fallback():
    entries = nday_lib.match_nday_by_title_server("通达OA办公系统登录页")
    assert entries, "标题含'通达OA'应兜底命中"
    assert all(e["fingerprint"] == "oa_tongda" for e in entries)


def test_match_by_title_no_hit():
    assert nday_lib.match_nday_by_title_server("某某公司官网首页") == []
    assert nday_lib.match_nday_by_title_server("") == []


# ---------- 渲染 ----------

def _sample_entry() -> dict:
    return {
        "id": "demo-x",
        "fingerprint": "demo_fp",
        "name": "演示检测",
        "vuln_type": "unauthorized_access",
        "severity_hint": "high",
        "check": {
            "method": "POST",
            "path": "/demo/api",
            "headers": {"Content-Type": "application/json"},
            "body": '{"a":1}',
        },
        "match": {"status_in": [200], "body_contains_all": ["ok"], "body_len_gt": 5},
        "next": "命中后按 unauthorized_access 提交",
        "harmless_note": "只读探测",
    }


def test_render_contains_callable_request_and_features():
    block = nday_lib.render_nday_block([_sample_entry()])
    assert block
    # 可照抄的调用 + 命中特征 + 无害性说明
    assert 'http_request(url="http://<目标>/demo/api"' in block
    assert 'method="POST"' in block
    assert "状态 [200]" in block
    assert "body 含 ok" in block
    assert "只读探测" in block
    assert block.endswith("\n\n")


def test_render_empty_returns_empty():
    assert nday_lib.render_nday_block([]) == ""


def test_render_total_limit():
    """总数上限 _MAX_TOTAL=6：多指纹大量条目只注入前 6 条。"""
    entries = []
    for i in range(10):
        e = _sample_entry()
        e["id"] = f"demo-{i}"
        e["fingerprint"] = f"fp_{i}"
        entries.append(e)
    block = nday_lib.render_nday_block(entries)
    assert block.count("## ") == nday_lib._MAX_TOTAL


def test_render_per_fp_limit():
    """每指纹上限 _MAX_PER_FP=2。"""
    entries = []
    for i in range(5):
        e = _sample_entry()
        e["id"] = f"demo-{i}"
        entries.append(e)
    block = nday_lib.render_nday_block(entries)
    assert block.count("## ") == nday_lib._MAX_PER_FP


def test_render_char_limit():
    """块级字数上限：超长条目被截断且不超 _MAX_INJECT_CHARS 太多。"""
    e = _sample_entry()
    e["next"] = "x" * 5000
    block = nday_lib.render_nday_block([e])
    assert len(block) <= nday_lib._MAX_INJECT_CHARS + 100  # 截断标记余量


# ---------- 损坏数据降级 ----------

def test_load_corrupted_json_returns_empty(monkeypatch, tmp_path: Path):
    """JSON 损坏时返回空 dict，绝不抛异常。"""
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(nday_lib, "_DATA_FILE", bad)
    monkeypatch.setattr(nday_lib, "_INDEX", None)
    monkeypatch.setattr(nday_lib, "_FALLBACK_TITLE", [])
    assert nday_lib.load_nday_index() == {}
    assert nday_lib.match_nday_by_fingerprint(["oa_tongda"]) == []


def test_load_missing_file_returns_empty(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(nday_lib, "_DATA_FILE", tmp_path / "nope.json")
    monkeypatch.setattr(nday_lib, "_INDEX", None)
    monkeypatch.setattr(nday_lib, "_FALLBACK_TITLE", [])
    assert nday_lib.load_nday_index() == {}


def test_entry_without_harmless_note_rejected(monkeypatch, tmp_path: Path):
    """红线门槛：缺 harmless_note 的条目不入库。"""
    import json as _json
    data = {"entries": [{
        "id": "no-note", "fingerprint": "fp_x", "name": "x",
        "check": {"method": "GET", "path": "/x"},
        "match": {"status_in": [200]},
    }]}
    f = tmp_path / "t.json"
    f.write_text(_json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(nday_lib, "_DATA_FILE", f)
    monkeypatch.setattr(nday_lib, "_INDEX", None)
    monkeypatch.setattr(nday_lib, "_FALLBACK_TITLE", [])
    assert nday_lib.load_nday_index() == {}
