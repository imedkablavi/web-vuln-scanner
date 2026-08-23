"""Scanner registry extension layer.

The hardened scanner implementation lives in ``core.scanner_base``.  Keeping the
registry extension small makes experimental detector registration auditable while
preserving the tested scanner runtime unchanged.
"""

from core import scanner_base as _base
from core.utils import logger
from plugins.host_header import HostHeaderPlugin
from plugins.ssrf import SSRFPlugin


PluginRegistry = _base.PluginRegistry
PluginRegistry.available.update(
    {
        "ssrf": SSRFPlugin,
        "host_header": HostHeaderPlugin,
    }
)
PluginRegistry.extended_experimental = {"ssrf", "host_header"}


def _load_plugins(cls, config, request_manager):
    plugins = []
    requested = config.get("plugins", {})
    blocked = set(cls.experimental) | set(getattr(cls, "extended_experimental", set()))
    for name, cfg in requested.items():
        cfg_obj = cfg if isinstance(cfg, dict) else {"enabled": bool(cfg)}
        plugin_cls = cls.available.get(name)
        if not plugin_cls:
            continue
        if name in blocked and cfg_obj.get("enabled"):
            logger.warning(f"Plugin '{name}' is disabled (experimental quality gate not satisfied). Skipping.")
            continue
        if plugin_cls.enabled(cfg_obj):
            plugins.append(plugin_cls(request_manager, cfg_obj))
    return plugins


PluginRegistry.load_plugins = classmethod(_load_plugins)
ScannerEngine = _base.ScannerEngine

__all__ = ["PluginRegistry", "ScannerEngine"]
