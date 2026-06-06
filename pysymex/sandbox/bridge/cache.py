# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping

from pysymex.config.sandbox_bridge import sandbox_config_fingerprint as _sandbox_config_fingerprint
from pysymex.core.cache.control import register_process_cache_clearer
from pysymex.sandbox.bridge.types import ModuleBlob
from pysymex.utils.hashing import stable_digest_hex

MODULE_CACHE_SIZE = 32
MODULE_CACHE: OrderedDict[tuple[str, str, str], ModuleBlob] = OrderedDict()


def module_cache_key(
    source: bytes,
    filename: str,
    sandbox_config: Mapping[str, object] | None,
) -> tuple[str, str, str]:
    """Build the process-local cache key for an extracted module payload.

    Args:
        source: Module source bytes submitted for extraction.
        filename: Staged module filename included in cache identity.
        sandbox_config: Optional sandbox-bridge configuration mapping.

    Returns:
        A tuple containing the source content digest, filename, and normalized
        sandbox configuration fingerprint.
    """
    return (
        stable_digest_hex(source),
        filename,
        _sandbox_config_fingerprint(sandbox_config),
    )


def remember_module_blob(key: tuple[str, str, str], blob: ModuleBlob) -> None:
    """Insert a module blob into the bounded process-local LRU cache.

    Args:
        key: Cache identity returned by `module_cache_key`.
        blob: Extracted module payload to retain.

    Side Effects:
        Stores or refreshes `key` in `MODULE_CACHE` and removes oldest entries
        while its size exceeds `MODULE_CACHE_SIZE`.
    """
    MODULE_CACHE[key] = blob
    MODULE_CACHE.move_to_end(key)
    while len(MODULE_CACHE) > MODULE_CACHE_SIZE:
        MODULE_CACHE.popitem(last=False)


def clear_module_extraction_cache() -> None:
    """Clear process-local sandbox module extraction cache."""
    MODULE_CACHE.clear()


register_process_cache_clearer(
    "sandbox.module_extraction_cache",
    clear_module_extraction_cache,
)
