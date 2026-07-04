from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class OAuthState:
    state: str
    owner_id: int
    scopes: list[str]
    created_at: int
    expires_at: int


@dataclass(frozen=True)
class OAuthAccount:
    owner_id: int
    discord_user_id: str
    username: str | None
    global_name: str | None
    access_token: str
    refresh_token: str
    token_type: str
    expires_at: int
    scopes: list[str]
    ip_address: str | None
    created_at: int
    updated_at: int

    @property
    def display_name(self) -> str:
        if self.global_name:
            return self.global_name
        if self.username:
            return self.username
        return self.discord_user_id

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


def scopes_to_json(scopes: list[str]) -> str:
    unique_scopes = []
    for scope in scopes:
        if scope not in unique_scopes:
            unique_scopes.append(scope)
    return json.dumps(unique_scopes)


def scopes_from_json(value: str | None) -> list[str]:
    if not value:
        return []

    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return []

    if not isinstance(decoded, list):
        return []

    return [str(item) for item in decoded]


def safe_user_payload(user: dict[str, Any]) -> dict[str, str | None]:
    return {
        "discord_user_id": str(user.get("id", "")),
        "username": user.get("username"),
        "global_name": user.get("global_name"),
    }
