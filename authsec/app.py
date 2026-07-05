from __future__ import annotations

import logging
import os
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from flask import Flask
from werkzeug.serving import BaseWSGIServer, make_server

from .bot import BotRuntime, create_bot
from .database import AuthDatabase
from .oauth import DiscordOAuthClient
from .settings import Settings, load_settings
from .web import create_web_app


logger = logging.getLogger(__name__)


@dataclass
class AuthSecApp:
    settings: Settings
    database: AuthDatabase
    oauth_client: DiscordOAuthClient
    bot_runtime: BotRuntime


def build_app(settings: Settings | None = None) -> AuthSecApp:
    settings = settings or load_settings()
    database = AuthDatabase(settings.database.path)
    oauth_client = DiscordOAuthClient(settings, database)
    bot_runtime = BotRuntime()
    return AuthSecApp(
        settings=settings,
        database=database,
        oauth_client=oauth_client,
        bot_runtime=bot_runtime,
    )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    app = build_app()
    web_app = create_web_app(app.oauth_client, app.bot_runtime)
    bot = create_bot(app.settings, app.oauth_client, app.bot_runtime)

    clear_web_port(app.settings)
    server = create_web_server(web_app, app.settings)
    logger.info(
        "OAuth website listening on %s:%s",
        app.settings.web.host,
        server.server_port,
    )
    threading.Thread(
        target=server.serve_forever,
        daemon=True,
        name="authsec-web",
    ).start()

    bot.run(app.settings.discord.token)


def create_web_server(web_app: Flask, settings: Settings) -> BaseWSGIServer:
    try:
        return make_server(
            settings.web.host,
            settings.web.port,
            web_app,
            threaded=True,
        )
    except OSError as exc:
        raise SystemExit(
            f"Could not start the OAuth website on {settings.web.host}:{settings.web.port}. "
            "Another process is using that address or the app cannot bind to it, "
            "so the Discord bot was not started."
        ) from exc


def clear_web_port(settings: Settings) -> None:
    if not settings.web.clear_port_before_start or settings.web.port <= 0:
        return

    pids = listening_pids_on_port(settings.web.port)
    pids.discard(os.getpid())
    protected_pids = {pid for pid in pids if pid <= 1}
    if protected_pids:
        raise SystemExit(
            f"Port {settings.web.port} is held by a protected system process. "
            "Stop that service first, then start AuthSec again."
        )

    if not pids:
        return

    logger.warning(
        "Stopping %s process(es) already listening on port %s: %s",
        len(pids),
        settings.web.port,
        ", ".join(str(pid) for pid in sorted(pids)),
    )
    stop_processes(pids, settings.web.port)


def listening_pids_on_port(port: int) -> set[int]:
    inodes = listening_socket_inodes(port)
    if not inodes:
        return set()

    proc = Path("/proc")
    if not proc.exists():
        return set()

    pids: set[int] = set()
    for pid_dir in proc.iterdir():
        if not pid_dir.name.isdigit():
            continue

        fd_dir = pid_dir / "fd"
        try:
            file_descriptors = list(fd_dir.iterdir())
        except OSError:
            continue

        for descriptor in file_descriptors:
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue

            if target.startswith("socket:[") and target[8:-1] in inodes:
                pids.add(int(pid_dir.name))
                break

    return pids


def listening_socket_inodes(port: int) -> set[str]:
    inodes: set[str] = set()
    for path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()[1:]
        except OSError:
            continue

        for line in lines:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "0A":
                continue

            _, _, local_port = parts[1].rpartition(":")
            try:
                socket_port = int(local_port, 16)
            except ValueError:
                continue

            if socket_port == port:
                inodes.add(parts[9])

    return inodes


def stop_processes(pids: set[int], port: int, timeout: float = 5.0) -> None:
    remaining = set(pids)
    for pid in sorted(remaining):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            remaining.discard(pid)
        except PermissionError as exc:
            raise SystemExit(
                f"Could not stop process {pid} on the web port. "
                "Run the app as a user with permission to stop that process."
            ) from exc

    deadline = time.monotonic() + timeout
    while remaining and time.monotonic() < deadline:
        remaining = remaining.intersection(listening_pids_on_port(port))
        if remaining:
            time.sleep(0.1)

    for pid in sorted(remaining):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            continue
        except PermissionError as exc:
            raise SystemExit(
                f"Could not force stop process {pid} on the web port. "
                "Run the app as a user with permission to stop that process."
            ) from exc
