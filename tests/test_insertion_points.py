from __future__ import annotations

from core.insertion_points import (
    json_document_from_inputs,
    json_value_inputs,
    mutate_json_inputs,
    schema_inputs,
    xml_value_inputs,
)
from core.models import AttackSurface, InputField
from plugins.sqli import SQLiPlugin
from plugins.xss_reflected import XSSReflectedPlugin


def test_json_value_inputs_preserve_distinct_nested_paths():
    points = json_value_inputs(
        {
            "owner": {"id": 7, "email": "owner@example.test"},
            "reviewer": {"id": 9},
            "items": [{"id": 11, "name": "first"}],
        }
    )
    paths = {item.path for item in points}
    assert "/owner/id" in paths
    assert "/reviewer/id" in paths
    assert "/owner/email" in paths
    assert "/items/0/id" in paths
    assert len([item for item in points if item.name == "id"]) == 3


def test_json_document_and_mutation_target_exact_pointer():
    inputs = json_value_inputs(
        {"owner": {"id": 7}, "reviewer": {"id": 9}}
    )
    rebuilt = json_document_from_inputs(inputs)
    assert rebuilt == {"owner": {"id": 7}, "reviewer": {"id": 9}}

    mutated = mutate_json_inputs(
        inputs,
        name="id",
        path="/reviewer/id",
        payload="CANARY",
    )
    assert mutated["owner"]["id"] == 7
    assert mutated["reviewer"]["id"] == "CANARY"


def test_ambiguous_nested_leaf_requires_canonical_path():
    inputs = json_value_inputs({"left": {"id": 1}, "right": {"id": 2}})
    try:
        mutate_json_inputs(inputs, name="id", payload="x")
    except ValueError as exc:
        assert "ambiguous" in str(exc).lower()
    else:
        raise AssertionError("duplicate nested leaf names must require a canonical path")


def test_schema_inputs_follow_local_ref_and_array_item():
    spec = {
        "components": {
            "schemas": {
                "Profile": {
                    "type": "object",
                    "required": ["email"],
                    "properties": {
                        "email": {"type": "string"},
                        "roles": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {"id": {"type": "integer"}},
                            },
                        },
                    },
                }
            }
        }
    }

    def resolve_ref(ref):
        assert ref == "#/components/schemas/Profile"
        return spec["components"]["schemas"]["Profile"]

    points = schema_inputs(
        {"$ref": "#/components/schemas/Profile"},
        resolve_ref=resolve_ref,
    )
    by_path = {item.path: item for item in points}
    assert by_path["/email"].required is True
    assert by_path["/email"].data_type == "string"
    assert by_path["/roles/0/id"].data_type == "integer"


def test_xml_inputs_reject_doctype_and_extract_safe_leaf_paths():
    unsafe = '<!DOCTYPE x [<!ENTITY e "secret">]><root><a>&e;</a></root>'
    assert xml_value_inputs(unsafe) == []

    safe = "<root><profile><email>a@example.test</email></profile></root>"
    points = xml_value_inputs(safe)
    assert [(item.path, item.name) for item in points] == [
        ("/root/profile/email", "email")
    ]


def test_site_surface_fingerprint_distinguishes_duplicate_leaf_paths():
    left = AttackSurface(
        url="https://example.test/api",
        method="POST",
        inputs=[InputField(name="id", kind="body", path="/owner/id")],
    )
    right = AttackSurface(
        url="https://example.test/api",
        method="POST",
        inputs=[InputField(name="id", kind="body", path="/reviewer/id")],
    )
    assert left.id != right.id


def test_stable_plugins_skip_nested_body_until_baseline_parity():
    surface = AttackSurface(
        url="https://example.test/api",
        method="POST",
        inputs=[
            InputField(name="top", value="x", kind="body", path="/top"),
            InputField(name="email", value="x", kind="body", path="/profile/email"),
        ],
        meta={"content_type": "application/json"},
    )
    sqli = SQLiPlugin(None, {"enabled": True, "max_tests_per_surface": 8})
    xss = XSSReflectedPlugin(None, {"enabled": True, "max_tests_per_surface": 8})

    sqli_tests = sqli.generate_tests(surface, {})
    xss_tests = xss.generate_tests(surface, {})

    assert any(test.param == "top" for test in sqli_tests)
    assert all(test.input_path != "/profile/email" for test in sqli_tests)
    assert any(test.param == "top" for test in xss_tests)
    assert all(test.input_path != "/profile/email" for test in xss_tests)
