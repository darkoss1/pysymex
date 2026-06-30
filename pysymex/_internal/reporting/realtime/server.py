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
from collections.abc import Callable
from http.server import HTTPServer

from pysymex._internal.logging.root import get_logger
from pysymex._internal.reporting.realtime.state import VisHandler

logger = get_logger(__name__)
UrlOpener = Callable[[str], object]
MessageSink = Callable[[str], None]
_REALTIME_URL = "http://127.0.0.1:8080"


def start_realtime_server(
    *,
    open_url: UrlOpener | None = None,
    message_sink: MessageSink | None = None,
) -> HTTPServer:
    """Start the local realtime visualization server."""
    server = HTTPServer(("127.0.0.1", 8080), VisHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    atexit.register(server.shutdown)
    if open_url is not None:
        open_url(_REALTIME_URL)
    _emit(message_sink, "\n" + "=" * 70)
    _emit(message_sink, "pysymex Live Directory Map Server Running!")
    _emit(message_sink, _REALTIME_URL)
    _emit(message_sink, "=" * 70 + "\n")
    _emit(message_sink, "Analyzing target directory paths and broadcasting dots data...")
    logger.verbose("Realtime visualization server started at %s", _REALTIME_URL)
    time.sleep(1.5)
    return server


def shutdown_realtime_server(
    server: HTTPServer,
    *,
    message_sink: MessageSink | None = None,
    delay_seconds: float = 120.0,
) -> None:
    """Delay briefly for browsing, then stop the visualization server."""
    _emit(message_sink, "[*] Symbolic network scan completion successful!")
    _emit(
        message_sink,
        f"[*] Will leave the graphical network server alive for {delay_seconds:g} seconds "
        "so you can browse the graph dots.",
    )
    logger.verbose("Realtime visualization server shutdown scheduled")
    time.sleep(delay_seconds)
    server.shutdown()
    logger.verbose("Realtime visualization server stopped")


def _emit(message_sink: MessageSink | None, message: str) -> None:
    if message_sink is not None:
        message_sink(message)
