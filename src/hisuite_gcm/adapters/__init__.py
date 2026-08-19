"""Registry for human-readable database adapters.

Built-in adapters are listed here. Third-party adapters register themselves
through the ``hisuite_gcm.adapters`` entry-point group::

    [project.entry-points."hisuite_gcm.adapters"]
    my-messenger = "my_package.adapter:MyMessengerAdapter"

The referenced object may be an adapter class or an already-built instance.
Adapters are advisory: a failure to import or detect one never stops raw,
authenticated extraction.
"""

from __future__ import annotations

import pathlib
from importlib import metadata

from .base import (
    Adapter,
    DetectionResult,
    ExportResult,
    as_text,
    column_names,
    is_sqlite,
    open_readonly,
    quote_identifier,
    requires_schema,
    table_names,
)
from .tables import SqliteTablesAdapter

ENTRY_POINT_GROUP = "hisuite_gcm.adapters"

__all__ = [
    "ENTRY_POINT_GROUP",
    "Adapter",
    "DetectionResult",
    "ExportResult",
    "SqliteTablesAdapter",
    "as_text",
    "available_adapters",
    "column_names",
    "detect_adapters",
    "find_adapter",
    "is_sqlite",
    "open_readonly",
    "quote_identifier",
    "requires_schema",
    "table_names",
]


def builtin_adapters() -> list[Adapter]:
    """Adapters shipped with this package."""

    return [SqliteTablesAdapter()]


def _plugin_adapters(warnings: list[str]) -> list[Adapter]:
    found: list[Adapter] = []
    try:
        entries = metadata.entry_points(group=ENTRY_POINT_GROUP)
    except Exception as error:  # pragma: no cover - depends on the environment
        warnings.append(f"could not list adapter plugins: {error}")
        return found
    for entry in entries:
        try:
            loaded = entry.load()
            adapter = loaded() if isinstance(loaded, type) else loaded
            if not isinstance(adapter, Adapter):
                warnings.append(f"adapter plugin {entry.name!r} does not implement the interface")
                continue
            found.append(adapter)
        except Exception as error:
            warnings.append(f"adapter plugin {entry.name!r} could not be loaded: {error}")
    return found


def available_adapters(
    *,
    include_plugins: bool = True,
    warnings: list[str] | None = None,
) -> list[Adapter]:
    """Return every usable adapter, built-in first, then plugins by name."""

    collected = list(builtin_adapters())
    if include_plugins:
        known = {adapter.name for adapter in collected}
        for adapter in sorted(
            _plugin_adapters(warnings if warnings is not None else []),
            key=lambda item: item.name,
        ):
            if adapter.name not in known:
                collected.append(adapter)
                known.add(adapter.name)
    return collected


def find_adapter(name: str, *, adapters: list[Adapter] | None = None) -> Adapter:
    """Return the adapter registered under ``name``."""

    candidates = available_adapters() if adapters is None else adapters
    for adapter in candidates:
        if adapter.name == name:
            return adapter
    known = ", ".join(sorted(adapter.name for adapter in candidates)) or "none"
    raise ValueError(f"unknown adapter {name!r}; available adapters: {known}")


def detect_adapters(
    database: pathlib.Path,
    *,
    adapters: list[Adapter] | None = None,
) -> list[tuple[Adapter, DetectionResult]]:
    """Ask every adapter whether it recognises ``database``."""

    candidates = available_adapters() if adapters is None else adapters
    connection = open_readonly(database)
    try:
        results: list[tuple[Adapter, DetectionResult]] = []
        for adapter in candidates:
            try:
                results.append((adapter, adapter.detect(connection)))
            except Exception as error:
                results.append(
                    (adapter, DetectionResult(False, f"detection raised an error: {error}"))
                )
        return results
    finally:
        connection.close()
