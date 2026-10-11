"""nuclei 模板生成/校验/mini-runner 单测。"""
from __future__ import annotations

from app.agents import nuclei_gen


GOOD_TEMPLATE = """id: test-nacos-unauth
info:
  name: Nacos 未授权检测
  severity: high
  x-autohunter-vuln-type: unauthorized_access
http:
  - method: GET
    path:
      - "{{BaseURL}}/nacos/v1/auth/users?pageNo=1&pageSize=1"
    matchers:
      - type: word
        words:
          - "username"
"""


# ---------- validate_template ----------

class TestValidateTemplate:
    def test_good_template_passes(self):
        ok, reason = nuclei_gen.validate_template(GOOD_TEMPLATE)
        assert ok, reason

    def test_empty_rejected(self):
        assert not nuclei_gen.validate_template("")[0]
        assert not nuclei_gen.validate_template("   \n")[0]

    def test_bad_yaml_rejected(self):
        assert not nuclei_gen.validate_template("{not: [valid")[0]

    def test_missing_id_rejected(self):
        bad = GOOD_TEMPLATE.replace("id: test-nacos-unauth\n", "")
        assert not nuclei_gen.validate_template(bad)[0]

    def test_missing_matchers_rejected(self):
        bad = GOOD_TEMPLATE.replace("      - type: word\n        words:\n          - \"username\"", "")
        assert not nuclei_gen.validate_template(bad)[0]

    def test_hardcoded_host_rejected(self):
        bad = GOOD_TEMPLATE.replace("{{BaseURL}}/nacos", "http://evil.example.com/nacos")
        ok, reason = nuclei_gen.validate_template(bad)
        assert not ok and "BaseURL" in reason

    def test_hardcoded_ip_rejected(self):
        bad = GOOD_TEMPLATE.replace("{{BaseURL}}/nacos", "http://203.0.113.5/nacos")
        assert not nuclei_gen.validate_template(bad)[0]

    def test_dangerous_method_rejected(self):
        bad = GOOD_TEMPLATE.replace("method: GET", "method: DELETE")
        ok, reason = nuclei_gen.validate_template(bad)
        assert not ok and "方法" in reason

    def test_dangerous_body_word_rejected(self):
        bad = GOOD_TEMPLATE.replace(
            '    matchers:\n',
            '    body: "a=1&sql=DROP TABLE users"\n    matchers:\n')
        assert not nuclei_gen.validate_template(bad)[0]

    def test_non_baseurl_path_rejected(self):
        bad = GOOD_TEMPLATE.replace("{{BaseURL}}/nacos", "/nacos")
        assert not nuclei_gen.validate_template(bad)[0]

    def test_root_not_mapping_rejected(self):
        assert not nuclei_gen.validate_template("- just\n- a\n- list\n")[0]


# ---------- safe_slug ----------

class TestSafeSlug:
    def test_chinese_and_slash_normalized(self):
        slug = nuclei_gen.safe_slug("通达OA/泛微", "arbitrary_file_read")
        assert slug == "arbitrary-file-read" or "-" in slug
        assert "/" not in slug and "\\" not in slug
        assert all(ord(c) < 128 for c in slug)

    def test_empty_fallback(self):
        assert nuclei_gen.safe_slug("", "") == "unknown-vuln"


# ---------- matcher 求值 ----------

class TestMatchHit:
    def test_status_matcher(self):
        m = [{"type": "status", "status": [200]}]
        assert nuclei_gen._match_hit(m, 200, "")
        assert not nuclei_gen._match_hit(m, 403, "")

    def test_word_matcher(self):
        m = [{"type": "word", "words": ["username"]}]
        assert nuclei_gen._match_hit(m, 200, '{"username":"admin"}')
        assert not nuclei_gen._match_hit(m, 200, '{"data":1}')

    def test_unknown_matcher_type_skipped(self):
        # 不认识的 matcher 类型：不命中（宁漏勿误）
        assert not nuclei_gen._match_hit([{"type": "dsl", "dsl": ["true"]}], 200, "x")

    def test_or_condition(self):
        m = [{"type": "status", "status": [200]}, {"type": "word", "words": ["x"]}]
        assert nuclei_gen._match_hit(m, 200, "no-keyword")  # or 语义

    def test_and_condition(self):
        m = [{"type": "status", "status": [200], "condition": "and"},
             {"type": "word", "words": ["token"], "condition": "and"}]
        assert nuclei_gen._match_hit(m, 200, "got token")
        assert not nuclei_gen._match_hit(m, 200, "nothing")


# ---------- save_template / load_sweep_templates ----------

def test_save_template_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setattr(nuclei_gen, "_TEMPLATE_ROOT", tmp_path)
    f = nuclei_gen.save_template("task1", "test-product", "unauthorized_access", GOOD_TEMPLATE)
    assert f is not None and f.exists()
    assert "task1" in str(f)
    assert f.name.startswith("test-product")

    loaded = nuclei_gen.load_sweep_templates()
    assert any(t["id"] == "test-nacos-unauth" for t in loaded)


def test_save_template_rejects_invalid(monkeypatch, tmp_path):
    monkeypatch.setattr(nuclei_gen, "_TEMPLATE_ROOT", tmp_path)
    bad = GOOD_TEMPLATE.replace("{{BaseURL}}", "http://evil.com")
    f = nuclei_gen.save_template("task1", "x", "y", bad)
    assert f is None
