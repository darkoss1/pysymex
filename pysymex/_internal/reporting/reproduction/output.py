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

"""Filesystem and script assembly helpers for reproductions."""

from __future__ import annotations

import os

from pysymex._internal.logging.root import get_logger
from pysymex._internal.reporting.reproduction.template import create_script_content

logger = get_logger(__name__)


class ReproductionOutputMixin:
    """Handle reproduction output paths and script content."""

    output_dir: str

    def _ensure_output_dir(self) -> None:
        """Create the output directory if it doesn't exist."""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            # Create __init__.py to make it a package
            init_file = os.path.join(self.output_dir, "__init__.py")
            if not os.path.exists(init_file):
                with open(init_file, "w") as f:
                    f.write("# pysymex reproductions package\n")
            from pysymex._internal.pathing import ensure_pysymex_gitignore

            ensure_pysymex_gitignore(self.output_dir)
        except OSError:
            logger.warning(
                "Failed to prepare reproduction output directory %s",
                self.output_dir,
                exc_info=True,
            )

    def _create_script_content(
        self,
        module_name: str,
        source_file: str,
        import_root: str,
        func_name: str,
        class_name: str | None,
        args_code: str,
        args_display: str,
        issue_kind: str,
        message: str,
    ) -> str:
        """Assemble the full reproduction-script source."""
        return create_script_content(
            module_name=module_name,
            source_file=source_file,
            import_root=import_root,
            func_name=func_name,
            class_name=class_name,
            args_code=args_code,
            args_display=args_display,
            issue_kind=issue_kind,
            message=message,
        )
