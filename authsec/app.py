from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

from .bot import BotRuntime, create_bot
from .database import AuthDatabase
from .oauth import DiscordOAuthClient
from .settings import Settings, load_settings
from .web import create_web_app


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

    threading.Thread(
        target=web_app.run,
        kwargs={
            "host": app.settings.web.host,
            "port": app.settings.web.port,
            "threaded": True,
            "use_reloader": False,
        },
        daemon=True,
        name="authsec-web",
    ).start()

    bot.run(app.settings.discord.token)
