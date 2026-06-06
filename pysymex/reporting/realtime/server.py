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

"""HTTP server lifecycle for realtime scans."""

from __future__ import annotations

import atexit
import threading
import time
import webbrowser
from http.server import HTTPServer

from pysymex.logger import get_logger
from pysymex.reporting.realtime.state import VisHandler

logger = get_logger(__name__)


def start_realtime_server() -> HTTPServer:
    """Start the local realtime visualization server."""
    server = HTTPServer(("127.0.0.1", 8080), VisHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    atexit.register(server.shutdown)
    webbrowser.open("http://127.0.0.1:8080")
    print("\n" + "=" * 70)
    print("pysymex Live Directory Map Server Running!")
    print("http://127.0.0.1:8080")
    print("=" * 70 + "\n")
    print("Analyzing target directory paths and broadcasting dots data...")
    logger.verbose("Realtime visualization server started at http://127.0.0.1:8080")
    time.sleep(1.5)
    return server


def shutdown_realtime_server(server: HTTPServer) -> None:
    """Delay briefly for browsing, then stop the visualization server."""
    print("[*] Symbolic network scan completion successful!")
    print(
        "[*] Will leave the graphical network server alive for 120 seconds so you can browse the graph dots."
    )
    logger.verbose("Realtime visualization server shutdown scheduled")
    time.sleep(120)
    server.shutdown()
    logger.verbose("Realtime visualization server stopped")


__all__ = ["shutdown_realtime_server", "start_realtime_server"]
