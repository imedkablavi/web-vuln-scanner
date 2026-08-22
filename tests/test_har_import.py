import pytest

from core.har_import import import_har_data


def har(entries):
    return {"log": {"version": "1.2", "creator": {"name": "fixture"}, "entries": entries}}


def entry(method, url, *, headers=None, post_data=None):
    return {
        "request": {
            "method": method,
            "url": url,
            "headers": headers or [],
            "postData": post_data or {},
        }
    }


def test_har_import_keeps_parameter_names_but_drops_values_and_secrets():
    data = har(
        [
            entry(
                "POST",
                "https://example.test/api/users?id=123&token=query-secret",
                headers=[
                    {"name": "Authorization", "value": "Bearer top-secret"},
                    {"name": "Cookie", "value": "session=cookie-secret"},
                    {"name": "Content-Type", "value": "application/json"},
                    {"name": "Accept", "value": "application/json"},
                ],
                post_data={
                    "mimeType": "application/json",
                    "text": '{"email":"person@example.test","password":"body-secret"}',
                },
            )
        ]
    )
    inventory = import_har_data(data, target="https://example.test/")
    assert inventory["sanitized"] is True
    assert inventory["summary"]["surfaces"] == 1
    surface = inventory["surfaces"][0]
    assert surface["url"] == "https://example.test/api/users"
    assert surface["params"] == {"id": "", "token": ""}
    fields = {(item["kind"], item["name"], item["value"]) for item in surface["inputs"]}
    assert ("body", "email", "") in fields
    assert ("body", "password", "") in fields
    rendered = repr(inventory)
    assert "top-secret" not in rendered
    assert "cookie-secret" not in rendered
    assert "query-secret" not in rendered
    assert "body-secret" not in rendered
    assert surface["meta"]["observed_header_names"] == ["Accept", "Content-Type"]


def test_har_import_drops_out_of_scope_entries():
    inventory = import_har_data(
        har(
            [
                entry("GET", "https://example.test/api/a"),
                entry("GET", "https://evil.test/api/b"),
            ]
        ),
        target="https://example.test/",
    )
    assert [item["url"] for item in inventory["surfaces"]] == [
        "https://example.test/api/a"
    ]
    assert inventory["summary"]["skipped"]["out_of_scope"] == 1


def test_har_import_deduplicates_by_method_url_and_input_shape():
    duplicate = entry("GET", "https://example.test/search?q=one")
    inventory = import_har_data(
        har([duplicate, entry("GET", "https://example.test/search?q=two")]),
        target="https://example.test/",
    )
    assert inventory["summary"]["surfaces"] == 1
    assert inventory["summary"]["skipped"]["duplicate"] == 1


def test_har_import_reads_form_parameter_names():
    inventory = import_har_data(
        har(
            [
                entry(
                    "POST",
                    "https://example.test/login",
                    post_data={
                        "mimeType": "application/x-www-form-urlencoded",
                        "params": [
                            {"name": "username", "value": "alice"},
                            {"name": "password", "value": "secret"},
                        ],
                    },
                )
            ]
        ),
        target="https://example.test/",
    )
    fields = {(item["kind"], item["name"]) for item in inventory["surfaces"][0]["inputs"]}
    assert fields == {("body", "username"), ("body", "password")}
    assert "alice" not in repr(inventory)
    assert "secret" not in repr(inventory)


def test_har_import_strips_request_url_userinfo():
    inventory = import_har_data(
        har([entry("GET", "https://alice:url-secret@example.test/api/profile?q=1")]),
        target="https://example.test/",
    )
    assert inventory["summary"]["surfaces"] == 1
    assert inventory["surfaces"][0]["url"] == "https://example.test/api/profile"
    assert "url-secret" not in repr(inventory)
    assert "alice@" not in repr(inventory)


def test_har_import_rejects_credentials_embedded_in_target_scope():
    with pytest.raises(ValueError, match="embedded URL credentials"):
        import_har_data(
            har([entry("GET", "https://example.test/")]),
            target="https://alice:secret@example.test/",
        )


def test_har_import_enforces_entry_budget():
    inventory = import_har_data(
        har(
            [
                entry("GET", "https://example.test/a"),
                entry("GET", "https://example.test/b"),
            ]
        ),
        target="https://example.test/",
        max_entries=1,
    )
    assert inventory["summary"]["entries_seen"] == 1
    assert inventory["summary"]["truncated"] is True
