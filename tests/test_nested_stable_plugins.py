from __future__ import annotations

from core.models import AttackSurface, InputField
from plugins.sqli import SQLiPlugin
from plugins.xss_reflected import XSSReflectedPlugin


def _surface(content_type="application/json", body_format="json"):
    return AttackSurface(
        url="https://example.com/api/review",
        method="POST",
        inputs=[
            InputField(name="id", value=7, kind="body", path="/owner/id", data_type="integer"),
            InputField(name="id", value=11, kind="body", path="/reviewer/id", data_type="integer"),
            InputField(name="name", value="alice", kind="body", path="/profile/name", data_type="string"),
        ],
        source="openapi",
        meta={
            "content_type": content_type,
            "body_format": body_format,
            "active_eligible": True,
        },
    )


def test_sqli_generates_distinct_nested_json_testcases():
    plugin = SQLiPlugin(None, {"enabled": True, "max_tests_per_surface": 20})
    tests = plugin.generate_tests(_surface(), {})

    paths = {test.input_path for test in tests}
    assert "/owner/id" in paths
    assert "/reviewer/id" in paths
    assert "/profile/name" in paths
    owner = [test for test in tests if test.input_path == "/owner/id"]
    reviewer = [test for test in tests if test.input_path == "/reviewer/id"]
    assert owner and reviewer
    assert all(test.param == "id" and test.kind == "body" for test in owner + reviewer)
    assert owner[0].baseline_key != reviewer[0].baseline_key


def test_reflected_markup_generates_distinct_nested_json_testcases():
    plugin = XSSReflectedPlugin(None, {"enabled": True, "max_tests_per_surface": 10})
    tests = plugin.generate_tests(_surface(), {})

    paths = {test.input_path for test in tests}
    assert "/owner/id" in paths
    assert "/reviewer/id" in paths
    assert "/profile/name" in paths


def test_nested_body_points_remain_inactive_for_xml():
    surface = _surface("text/xml", "xml")
    sqli = SQLiPlugin(None, {"enabled": True, "max_tests_per_surface": 20})
    xss = XSSReflectedPlugin(None, {"enabled": True, "max_tests_per_surface": 20})

    assert sqli.generate_tests(surface, {}) == []
    assert xss.generate_tests(surface, {}) == []


def test_nested_body_points_remain_inactive_for_form_encoding():
    surface = _surface("application/x-www-form-urlencoded", "form")
    sqli = SQLiPlugin(None, {"enabled": True, "max_tests_per_surface": 20})
    xss = XSSReflectedPlugin(None, {"enabled": True, "max_tests_per_surface": 20})

    assert sqli.generate_tests(surface, {}) == []
    assert xss.generate_tests(surface, {}) == []
