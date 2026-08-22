from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable
from urllib.parse import urlparse

from .models import AttackSurface, InputField
from .utils import normalize_url


class SiteMapBuilder:
    """Build a secret-minimized application map from assessment observations.

    URLs are stored without query values/fragments. Input names and locations are
    retained because they describe attack-surface coverage without persisting the
    original parameter values.
    """

    def __init__(self, max_entries: int = 5000):
        self.max_entries = max(1, int(max_entries or 5000))
        self._entries: Dict[str, Dict[str, Any]] = {}
        self.truncated = False

    @staticmethod
    def _base_url(url: str) -> str:
        return normalize_url(str(url or ""))

    @staticmethod
    def _clean_inputs(inputs: Iterable[InputField] | None) -> list[dict[str, str]]:
        cleaned: list[dict[str, str]] = []
        seen = set()
        for item in inputs or []:
            name = str(getattr(item, "name", "") or "").strip()
            kind = str(getattr(item, "kind", "query") or "query").strip().lower()
            if not name:
                continue
            key = (name, kind)
            if key in seen:
                continue
            seen.add(key)
            cleaned.append({"name": name, "kind": kind})
        return cleaned

    def record_url(
        self,
        url: str,
        *,
        source: str,
        method: str = "GET",
        requested: bool = False,
        depth: int | None = None,
        actor_id: str = "",
        inputs: Iterable[InputField] | None = None,
        surface_id: str = "",
    ) -> None:
        base_url = self._base_url(url)
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return

        if base_url not in self._entries and len(self._entries) >= self.max_entries:
            self.truncated = True
            return

        entry = self._entries.setdefault(
            base_url,
            {
                "url": base_url,
                "host": parsed.netloc,
                "path": parsed.path or "/",
                "methods": set(),
                "sources": set(),
                "requested": False,
                "min_depth": None,
                "actors": set(),
                "input_points": {},
                "surface_ids": set(),
            },
        )
        entry["methods"].add(str(method or "GET").upper())
        entry["sources"].add(str(source or "unknown"))
        entry["requested"] = bool(entry["requested"] or requested)
        if depth is not None:
            parsed_depth = max(0, int(depth))
            if entry["min_depth"] is None or parsed_depth < entry["min_depth"]:
                entry["min_depth"] = parsed_depth
        if actor_id:
            entry["actors"].add(str(actor_id))
        for item in self._clean_inputs(inputs):
            key = f"{item['kind']}:{item['name']}"
            entry["input_points"][key] = item
        if surface_id:
            entry["surface_ids"].add(str(surface_id))

    def record_surface(
        self,
        surface: AttackSurface,
        *,
        requested: bool = False,
        actor_id: str = "",
    ) -> None:
        inputs = list(surface.inputs or [])
        existing = {(item.name, item.kind) for item in inputs}
        for name in (surface.params or {}).keys():
            if (name, "query") not in existing:
                inputs.append(InputField(name=name, value=None, kind="query"))
        self.record_url(
            surface.url,
            source=surface.source,
            method=surface.method,
            requested=requested,
            depth=(surface.meta or {}).get("depth"),
            actor_id=actor_id or (surface.meta or {}).get("visible_to_actor", ""),
            inputs=inputs,
            surface_id=surface.id,
        )

    def merge_report(self, report: Dict[str, Any] | None) -> None:
        """Merge another serialized site map without reintroducing raw values."""
        if not isinstance(report, dict):
            return
        self.truncated = bool(self.truncated or report.get("summary", {}).get("truncated"))
        for entry in report.get("entries", []) or []:
            if not isinstance(entry, dict):
                continue
            url = str(entry.get("url", "") or "")
            methods = [str(item) for item in (entry.get("methods", []) or ["GET"])]
            sources = [str(item) for item in (entry.get("sources", []) or ["unknown"])]
            actors = [str(item) for item in (entry.get("actors", []) or []) if str(item)]
            raw_inputs = entry.get("input_points", []) or []
            inputs = [
                InputField(
                    name=str(item.get("name", "") or ""),
                    value=None,
                    kind=str(item.get("kind", "query") or "query"),
                )
                for item in raw_inputs
                if isinstance(item, dict) and str(item.get("name", "") or "").strip()
            ]
            surface_ids = [
                str(item) for item in (entry.get("surface_ids", []) or []) if str(item)
            ]
            for source in sources:
                for method in methods:
                    if actors:
                        for actor_id in actors:
                            self.record_url(
                                url,
                                source=source,
                                method=method,
                                requested=bool(entry.get("requested", False)),
                                depth=entry.get("min_depth"),
                                actor_id=actor_id,
                                inputs=inputs,
                            )
                    else:
                        self.record_url(
                            url,
                            source=source,
                            method=method,
                            requested=bool(entry.get("requested", False)),
                            depth=entry.get("min_depth"),
                            inputs=inputs,
                        )
            base_url = self._base_url(url)
            if base_url in self._entries:
                self._entries[base_url]["surface_ids"].update(surface_ids)

    def to_dict(self) -> Dict[str, Any]:
        serialized = []
        source_counts: Counter[str] = Counter()
        method_counts: Counter[str] = Counter()
        input_kind_counts: Counter[str] = Counter()
        requested_count = 0

        for key in sorted(self._entries):
            raw = self._entries[key]
            methods = sorted(raw["methods"])
            sources = sorted(raw["sources"])
            input_points = sorted(
                raw["input_points"].values(),
                key=lambda item: (item["kind"], item["name"]),
            )
            for source in sources:
                source_counts[source] += 1
            for method in methods:
                method_counts[method] += 1
            for item in input_points:
                input_kind_counts[item["kind"]] += 1
            requested_count += int(bool(raw["requested"]))
            serialized.append(
                {
                    "url": raw["url"],
                    "host": raw["host"],
                    "path": raw["path"],
                    "methods": methods,
                    "sources": sources,
                    "requested": bool(raw["requested"]),
                    "min_depth": raw["min_depth"],
                    "actors": sorted(raw["actors"]),
                    "input_points": input_points,
                    "surface_ids": sorted(raw["surface_ids"]),
                }
            )

        return {
            "schema": "webvulnscanner/site-map/1.0",
            "summary": {
                "urls": len(serialized),
                "requested_urls": requested_count,
                "discovered_only_urls": max(0, len(serialized) - requested_count),
                "input_points": sum(input_kind_counts.values()),
                "by_source": dict(sorted(source_counts.items())),
                "by_method": dict(sorted(method_counts.items())),
                "input_points_by_kind": dict(sorted(input_kind_counts.items())),
                "truncated": self.truncated,
                "max_entries": self.max_entries,
            },
            "entries": serialized,
        }

    def write(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
        return destination
