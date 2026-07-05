from __future__ import annotations

import json
import os
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
    sync_commands: bool = True
    guild_id: int | None = None


@dataclass(frozen=True)
class WebSettings:
    host: str = "0.0.0.0"
    port: int = 80
    redirect_uri: str = DEFAULT_REDIRECT_URI
    force_https: bool = True
    clear_port_before_start: bool = True


@dataclass(frozen=True)
class DatabaseSettings:
    path: Path = DEFAULT_DATABASE_PATH


@dataclass(frozen=True)
class OAuthSettings:
    request_timeout: int = 10
    refresh_before_expiry_seconds: int = 14 * 24 * 60 * 60
    state_ttl_seconds: int = 10 * 60


@dataclass(frozen=True)
class IPGeoSettings:
    api_key: str | None = None
    base_url: str = "https://api.getipgeo.com"


@dataclass(frozen=True)
class Settings:
    discord: DiscordSettings
    web: WebSettings
    database: DatabaseSettings
    oauth: OAuthSettings
    ipgeo: IPGeoSettings


def load_settings(path: Path = CONFIG_PATH) -> Settings:
    raw = _load_config_file(path)

    discord = _dict(raw.get("discord"))
    web = _dict(raw.get("web"))
    database = _dict(raw.get("database"))
    oauth = _dict(raw.get("oauth"))
    ipgeo = _dict(raw.get("ipgeo"))

    token = _first_value(
        discord,
        raw,
        ("token", "bot_token", "discord_token"),
        ("DISCORD_TOKEN", "BOT_TOKEN", "AUTHSEC_DISCORD_TOKEN"),
    )
    client_id = _first_value(
        discord,
        raw,
        ("client_id", "application_id", "id"),
        ("DISCORD_CLIENT_ID", "DISCORD_APPLICATION_ID", "AUTHSEC_CLIENT_ID"),
    )
    client_secret = (
        _first_value(
            discord,
            raw,
            ("client_secret", "secret"),
            ("DISCORD_CLIENT_SECRET", "AUTHSEC_CLIENT_SECRET"),
        )
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
        raise RuntimeError(
            f"Missing required config value(s): {joined}. "
            f"Checked {path} plus DISCORD_TOKEN, DISCORD_CLIENT_ID, "
            "and DISCORD_CLIENT_SECRET environment variables."
        )

    database_path = _resolve_path(database.get("path"), DEFAULT_DATABASE_PATH)
    web_host = _first_value(
        web,
        raw,
        ("host", "web_host"),
        ("AUTHSEC_WEB_HOST", "WEB_HOST"),
    )
    web_port = _first_value(
        web,
        raw,
        ("port", "web_port"),
        ("AUTHSEC_WEB_PORT", "WEB_PORT", "PORT"),
    )
    redirect_uri = _first_value(
        web,
        raw,
        ("redirect_uri", "callback_url"),
        ("AUTHSEC_REDIRECT_URI", "DISCORD_REDIRECT_URI"),
    )
    force_https = _first_value(
        web,
        raw,
        ("force_https",),
        ("AUTHSEC_FORCE_HTTPS",),
    )
    clear_port_before_start = _first_value(
        web,
        raw,
        ("clear_port_before_start", "stop_port_processes"),
        ("AUTHSEC_CLEAR_WEB_PORT", "AUTHSEC_STOP_PORT_PROCESSES"),
    )
    ipgeo_api_key = _first_value(
        ipgeo,
        raw,
        ("api_key", "key"),
        ("AUTHSEC_IPGEO_API_KEY", "IPGEO_API_KEY"),
    )
    ipgeo_base_url = _first_value(
        ipgeo,
        raw,
        ("base_url",),
        ("AUTHSEC_IPGEO_BASE_URL",),
    )

    return Settings(
        discord=DiscordSettings(
            token=str(token),
            client_id=str(client_id),
            client_secret=str(client_secret),
            sync_commands=bool(discord.get("sync_commands", True)),
            guild_id=_optional_int(discord.get("guild_id")),
        ),
        web=WebSettings(
            host=str(web_host or "0.0.0.0"),
            port=int(web_port or 80),
            redirect_uri=str(redirect_uri or DEFAULT_REDIRECT_URI),
            force_https=_bool_value(force_https, True),
            clear_port_before_start=_bool_value(clear_port_before_start, True),
        ),
        database=DatabaseSettings(path=database_path),
        oauth=OAuthSettings(
            request_timeout=int(oauth.get("request_timeout", 10)),
            refresh_before_expiry_seconds=int(
                oauth.get("refresh_before_expiry_seconds", 14 * 24 * 60 * 60)
            ),
            state_ttl_seconds=int(oauth.get("state_ttl_seconds", 10 * 60)),
        ),
        ipgeo=IPGeoSettings(
            api_key=str(ipgeo_api_key).strip() if ipgeo_api_key else None,
            base_url=str(ipgeo_base_url or "https://api.getipgeo.com").rstrip("/"),
        ),
    )


def _dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _load_config_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as file:
        raw = json.load(file)

    if not isinstance(raw, dict):
        raise RuntimeError(f"{path} must contain a JSON object.")

    return raw


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return int(value)


def _bool_value(value: Any, default: bool) -> bool:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0

    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _first_value(
    nested: dict[str, Any],
    root: dict[str, Any],
    keys: tuple[str, ...],
    environment_keys: tuple[str, ...],
) -> Any:
    for key in keys:
        if nested.get(key):
            return nested[key]
        if root.get(key):
            return root[key]

    for key in environment_keys:
        if os.environ.get(key):
            return os.environ[key]

    return None


def _resolve_path(value: Any, default: Path) -> Path:
    if not value:
        return default

    path = Path(str(value))
    if path.is_absolute():
        return path
    return BASE_DIR / path
