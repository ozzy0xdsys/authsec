from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.json"
DEFAULT_DATABASE_PATH = BASE_DIR / "authsec.sqlite3"
DEFAULT_REDIRECT_URI = "https://authsec.xyz/callback"


@dataclass(frozen=True)
class DiscordSettings:
    token: str
    client_id: str
    client_secret: str
    command_prefix: str = "!"
    sync_commands: bool = True
    guild_id: int | None = None


@dataclass(frozen=True)
class WebSettings:
    host: str = "0.0.0.0"
    port: int = 80
    redirect_uri: str = DEFAULT_REDIRECT_URI
    force_https: bool = True


@dataclass(frozen=True)
class DatabaseSettings:
    path: Path = DEFAULT_DATABASE_PATH


@dataclass(frozen=True)
class OAuthSettings:
    request_timeout: int = 10
    refresh_before_expiry_seconds: int = 14 * 24 * 60 * 60
    state_ttl_seconds: int = 10 * 60


@dataclass(frozen=True)
class Settings:
    discord: DiscordSettings
    web: WebSettings
    database: DatabaseSettings
    oauth: OAuthSettings


def load_settings(path: Path = CONFIG_PATH) -> Settings:
    with path.open("r", encoding="utf-8") as file:
        raw = json.load(file)

    discord = _dict(raw.get("discord"))
    web = _dict(raw.get("web"))
    database = _dict(raw.get("database"))
    oauth = _dict(raw.get("oauth"))

    token = discord.get("token") or raw.get("token")
    client_id = discord.get("client_id") or discord.get("id") or raw.get("id")
    client_secret = (
        discord.get("client_secret")
        or discord.get("secret")
        or raw.get("secret")
    )

    missing = [
        name
        for name, value in {
            "token": token,
            "client_id": client_id,
            "client_secret": client_secret,
        }.items()
        if not value
    ]
    if missing:
        joined = ", ".join(missing)
        raise RuntimeError(f"Missing required config value(s): {joined}")

    database_path = _resolve_path(database.get("path"), DEFAULT_DATABASE_PATH)

    return Settings(
        discord=DiscordSettings(
            token=str(token),
            client_id=str(client_id),
            client_secret=str(client_secret),
            command_prefix=str(discord.get("command_prefix", "!")),
            sync_commands=bool(discord.get("sync_commands", True)),
            guild_id=_optional_int(discord.get("guild_id")),
        ),
        web=WebSettings(
            host=str(web.get("host", "0.0.0.0")),
            port=int(web.get("port", 80)),
            redirect_uri=str(web.get("redirect_uri", DEFAULT_REDIRECT_URI)),
            force_https=bool(web.get("force_https", True)),
        ),
        database=DatabaseSettings(path=database_path),
        oauth=OAuthSettings(
            request_timeout=int(oauth.get("request_timeout", 10)),
            refresh_before_expiry_seconds=int(
                oauth.get("refresh_before_expiry_seconds", 14 * 24 * 60 * 60)
            ),
            state_ttl_seconds=int(oauth.get("state_ttl_seconds", 10 * 60)),
        ),
    )


def _dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return int(value)


def _resolve_path(value: Any, default: Path) -> Path:
    if not value:
        return default

    path = Path(str(value))
    if path.is_absolute():
        return path
    return BASE_DIR / path
