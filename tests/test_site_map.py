import json

from core.models import AttackSurface, InputField
from core.site_map import SiteMapBuilder


def test_site_map_merges_sources_and_drops_query_values(tmp_path):
    builder = SiteMapBuilder(max_entries=10)
    builder.record_url(
        "https://example.test/search?q=visible&token=SUPERSECRET#frag",
        source="html-link",
        requested=False,
        depth=2,
    )
    builder.record_url(
        "https://example.test/search?q=other",
        source="crawler-response",
        requested=True,
        depth=1,
        actor_id="low_user",
    )
    surface = AttackSurface(
        url="https://example.test/search",
        method="GET",
        params={"q": "visible", "token": "SUPERSECRET"},
        inputs=[
            InputField(name="q", value="visible", kind="query"),
            InputField(name="token", value="SUPERSECRET", kind="query"),
        ],
        source="html-form",
        meta={"depth": 1},
    )
    builder.record_surface(surface)

    report = builder.to_dict()
    assert report["summary"]["urls"] == 1
    assert report["summary"]["requested_urls"] == 1
    entry = report["entries"][0]
    assert entry["url"] == "https://example.test/search"
    assert entry["sources"] == ["crawler-response", "html-form", "html-link"]
    assert entry["actors"] == ["low_user"]
    assert {item["name"] for item in entry["input_points"]} == {"q", "token"}

    output = builder.write(tmp_path / "site_map.json")
    text = output.read_text(encoding="utf-8")
    assert "SUPERSECRET" not in text
    assert "visible" not in text
    assert json.loads(text)["schema"] == "webvulnscanner/site-map/1.1"


def test_site_map_keeps_nested_paths_but_not_nested_values(tmp_path):
    builder = SiteMapBuilder(max_entries=10)
    surface = AttackSurface(
        url="https://example.test/api/user",
        method="PATCH",
        inputs=[
            InputField(
                name="id",
                value="FIRST-SECRET",
                kind="body",
                path="/owner/id",
                data_type="string",
                required=True,
            ),
            InputField(
                name="id",
                value="SECOND-SECRET",
                kind="body",
                path="/reviewer/id",
                data_type="string",
            ),
        ],
        source="postman",
    )
    builder.record_surface(surface)

    output = builder.write(tmp_path / "site_map.json")
    data = json.loads(output.read_text(encoding="utf-8"))
    entry = data["entries"][0]
    by_path = {item["path"]: item for item in entry["input_points"]}
    assert set(by_path) == {"/owner/id", "/reviewer/id"}
    assert by_path["/owner/id"]["required"] is True
    assert by_path["/owner/id"]["data_type"] == "string"
    rendered = output.read_text(encoding="utf-8")
    assert "FIRST-SECRET" not in rendered
    assert "SECOND-SECRET" not in rendered


def test_site_map_enforces_entry_cap():
    builder = SiteMapBuilder(max_entries=1)
    builder.record_url("https://example.test/one", source="crawler-response")
    builder.record_url("https://example.test/two", source="crawler-response")

    report = builder.to_dict()
    assert report["summary"]["urls"] == 1
    assert report["summary"]["truncated"] is True
