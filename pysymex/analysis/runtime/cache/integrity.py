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

"""Keyed BLAKE2b integrity protection for persistent cache blobs."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from pathlib import Path
from typing import Final

from pysymex.logger import get_logger

logger = get_logger(__name__)

BLAKE2B_KEY_SIZE: Final[int] = 64
BLAKE2B_TAG_SIZE: Final[int] = 64


def _blake2b_mac(key: bytes, payload: bytes) -> bytes:
    """Return a keyed BLAKE2b digest used as an authentication tag."""
    return hashlib.blake2b(payload, key=key, digest_size=BLAKE2B_TAG_SIZE).digest()


class CacheIntegrity:
    """Keyed BLAKE2b signing and verification for persistent cache blobs.

    Manages a secret key stored at *key_path*.  The key is created
    (with restricted file permissions) on first use and cached in
    memory.  If the key file is missing or corrupt, it is regenerated,
    which effectively invalidates all previously signed entries.
    """

    def __init__(self, key_path: Path) -> None:
        """Initialize a CacheIntegrity instance for persistent signing.

        Args:
            key_path (Path): Path to load or generate the MAC secret key.
        """
        self._key_path = key_path
        self._key: bytes | None = None

    def _restrict_key_permissions(self) -> None:
        """Restrict the key file to owner-only read/write (best effort on Windows)."""
        try:
            self._key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            logger.debug("Failed to tighten cache key permissions", exc_info=True)

    def _write_key_file(self, key: bytes) -> None:
        """Write *key* to disk with restricted permissions using ``os.open``."""
        fd = os.open(
            self._key_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
        self._restrict_key_permissions()

    def _load_or_create_key(self) -> bytes:
        """Load the MAC key from disk, or generate a fresh one if absent or corrupt."""
        if self._key is not None:
            return self._key
        if self._key_path.exists():
            raw = self._key_path.read_bytes()
            if len(raw) == BLAKE2B_KEY_SIZE:
                self._restrict_key_permissions()
                self._key = raw
                return raw
            logger.warning("Corrupt cache MAC key file - regenerating")
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        from pysymex.pathing import ensure_pysymex_gitignore

        ensure_pysymex_gitignore(self._key_path.parent)
        key = secrets.token_bytes(BLAKE2B_KEY_SIZE)
        self._write_key_file(key)
        self._key = key
        return key

    def sign(self, key_str: str | bytes, blob: bytes | None = None) -> bytes:
        """Return ``tag || blob`` where *tag* is keyed BLAKE2b over ``key_str + '\\0' + blob``.

        If *blob* is ``None``, *key_str* is used as both the blob and
        the key defaults to ``"__global__"``.
        """
        if blob is None:
            blob = key_str.encode("utf-8") if isinstance(key_str, str) else key_str
            key_str = "__global__"
        key = self._load_or_create_key()
        payload = str(key_str).encode("utf-8") + b"\0" + blob
        tag = _blake2b_mac(key, payload)
        return tag + blob

    def verify_and_extract(
        self,
        key_str: str | bytes,
        signed_blob: bytes | None = None,
    ) -> bytes | None:
        """Verify the BLAKE2b tag and return the raw blob, or ``None`` on failure.

        If *signed_blob* is ``None``, *key_str* is treated as the signed
        blob with key ``"__global__"``.
        """
        if signed_blob is None:
            signed_blob = key_str.encode("utf-8") if isinstance(key_str, str) else key_str
            key_str = "__global__"
        if len(signed_blob) < BLAKE2B_TAG_SIZE:
            return None
        tag = signed_blob[:BLAKE2B_TAG_SIZE]
        blob = signed_blob[BLAKE2B_TAG_SIZE:]
        key = self._load_or_create_key()
        payload = str(key_str).encode("utf-8") + b"\0" + blob
        expected = _blake2b_mac(key, payload)
        if secrets.compare_digest(tag, expected):
            return blob
        return None

    def reset_key(self) -> None:
        """Delete the key file, invalidating all signed entries on next access."""
        self._key = None
        if self._key_path.exists():
            self._key_path.unlink()


__all__ = ["BLAKE2B_KEY_SIZE", "BLAKE2B_TAG_SIZE", "CacheIntegrity"]
