from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

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
