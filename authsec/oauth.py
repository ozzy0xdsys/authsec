from __future__ import annotations

import secrets
import time
from dataclasses import replace
from typing import Any
from urllib.parse import urlencode

import requests

from .database import AuthDatabase
from .models import OAuthAccount, safe_user_payload
from .settings import Settings


API_BASE_URL = "https://discord.com/api/v10"
AUTHORIZE_URL = "https://discord.com/oauth2/authorize"


class DiscordApiError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class DiscordOAuthClient:
    def __init__(self, settings: Settings, database: AuthDatabase):
        self.settings = settings
        self.database = database
        self.session = requests.Session()

    def build_authorization_url(self, owner_id: int, scopes: list[str]) -> str:
        clean_scopes = normalize_scopes(scopes)
        state = secrets.token_urlsafe(32)
        self.database.cleanup_states()
        self.database.save_state(
            state=state,
            owner_id=int(owner_id),
            scopes=clean_scopes,
            ttl_seconds=self.settings.oauth.state_ttl_seconds,
        )

        params = {
            "client_id": self.settings.discord.client_id,
            "response_type": "code",
            "redirect_uri": self.settings.web.redirect_uri,
            "scope": " ".join(clean_scopes),
            "state": state,
        }
        return f"{AUTHORIZE_URL}?{urlencode(params)}"

    def complete_authorization(
        self,
        code: str,
        state: str,
        ip_address: str | None,
    ) -> OAuthAccount:
        saved_state = self.database.consume_state(state)
        if saved_state is None:
            raise DiscordApiError("This authorization link expired or was already used.", 400)

        token = self._exchange_code(code)
        access_token = _required(token, "access_token")
        refresh_token = _required(token, "refresh_token")
        user = self.fetch_current_user_with_token(access_token)
        user_payload = safe_user_payload(user)
        discord_user_id = user_payload["discord_user_id"]
        if not discord_user_id:
            raise DiscordApiError("Discord did not return a user id.", 502)

        now = int(time.time())
        webhook = _webhook_fields(token.get("webhook"))
        account = OAuthAccount(
            owner_id=saved_state.owner_id,
            discord_user_id=discord_user_id,
            username=user_payload["username"],
            global_name=user_payload["global_name"],
            mfa_enabled=user_payload["mfa_enabled"],
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=str(token.get("token_type", "Bearer")),
            expires_at=now + int(token.get("expires_in", 3600)),
            scopes=normalize_scopes(token.get("scope", "").split() or saved_state.scopes),
            ip_address=ip_address,
            created_at=now,
            updated_at=now,
            **webhook,
        )
        saved = self.database.save_account(account)
        self.database.log_event("oauth_connected", saved.owner_id, saved.discord_user_id)
        return saved

    def get_account(
        self,
        owner_id: int,
        refresh_if_needed: bool = True,
    ) -> OAuthAccount | None:
        account = self.database.get_account(owner_id)
        if account is None or not refresh_if_needed:
            return account

        seconds_left = account.expires_at - int(time.time())
        if seconds_left > self.settings.oauth.refresh_before_expiry_seconds:
            return account

        return self.refresh_account(owner_id, force=True)

    def refresh_account(self, owner_id: int, force: bool = False) -> OAuthAccount:
        account = self.database.get_account(owner_id)
        if account is None:
            raise DiscordApiError("No linked OAuth account was found.", 404)

        seconds_left = account.expires_at - int(time.time())
        if not force and seconds_left > self.settings.oauth.refresh_before_expiry_seconds:
            return account

        token = self._refresh_token(account.refresh_token)
        now = int(time.time())
        access_token = _required(token, "access_token")
        user_payload = safe_user_payload(self.fetch_current_user_with_token(access_token))
        webhook = _webhook_fields(token.get("webhook"), account)
        updated = replace(
            account,
            username=user_payload["username"] or account.username,
            global_name=user_payload["global_name"] or account.global_name,
            mfa_enabled=(
                user_payload["mfa_enabled"]
                if user_payload["mfa_enabled"] is not None
                else account.mfa_enabled
            ),
            access_token=access_token,
            refresh_token=str(token.get("refresh_token") or account.refresh_token),
            token_type=str(token.get("token_type", account.token_type)),
            expires_at=now + int(token.get("expires_in", 3600)),
            scopes=normalize_scopes(token.get("scope", "").split() or account.scopes),
            updated_at=now,
            **webhook,
        )
        saved = self.database.save_account(updated)
        self.database.log_event("oauth_refreshed", saved.owner_id, saved.discord_user_id)
        return saved

    def disconnect_account(self, owner_id: int) -> bool:
        account = self.database.get_account(owner_id)
        if account is None:
            return False

        revoked = False
        try:
            self._revoke_token(account.refresh_token)
            revoked = True
        except DiscordApiError:
            try:
                self._revoke_token(account.access_token)
                revoked = True
            except DiscordApiError:
                revoked = False

        self.database.delete_account(owner_id)
        self.database.log_event("oauth_disconnected", owner_id, account.discord_user_id)
        return revoked

    def fetch_current_user(self, owner_id: int) -> dict[str, Any]:
        account = self._required_account(owner_id)
        return self.fetch_current_user_with_token(account.access_token)

    def fetch_current_user_with_token(self, access_token: str) -> dict[str, Any]:
        return self._request_json(
            "GET",
            "/users/@me",
            headers=_bearer_headers(access_token),
        )

    def fetch_guilds(self, owner_id: int) -> list[dict[str, Any]]:
        account = self._required_account(owner_id)
        _require_scope(account, "guilds")
        payload = self._request_json(
            "GET",
            "/users/@me/guilds",
            headers=_bearer_headers(account.access_token),
            params={"with_counts": "true"},
        )
        if isinstance(payload, list):
            return payload
        raise DiscordApiError("Discord returned an unexpected guild list.", 502)

    def fetch_guild_member_details(
        self,
        owner_id: int,
        guild_ids: list[str],
    ) -> dict[str, dict[str, Any]]:
        account = self._required_account(owner_id)
        _require_scope(account, "guilds.members.read")

        details = {}
        for guild_id in guild_ids:
            if not guild_id:
                continue

            try:
                payload = self._request_json(
                    "GET",
                    f"/users/@me/guilds/{guild_id}/member",
                    headers=_bearer_headers(account.access_token),
                )
            except DiscordApiError:
                continue

            if isinstance(payload, dict):
                details[str(guild_id)] = payload

        return details

    def fetch_connections(self, owner_id: int) -> list[dict[str, Any]]:
        account = self._required_account(owner_id)
        _require_scope(account, "connections")
        payload = self._request_json(
            "GET",
            "/users/@me/connections",
            headers=_bearer_headers(account.access_token),
        )
        if isinstance(payload, list):
            return payload
        raise DiscordApiError("Discord returned an unexpected connection list.", 502)

    def fetch_relationships(self, owner_id: int) -> list[dict[str, Any]]:
        account = self._required_account(owner_id)
        _require_scope(account, "relationships.read")
        payload = self._request_json(
            "GET",
            "/users/@me/relationships",
            headers=_bearer_headers(account.access_token),
        )
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict) and isinstance(payload.get("relationships"), list):
            return payload["relationships"]
        raise DiscordApiError("Discord returned an unexpected relationship list.", 502)

    def add_to_guild(self, owner_id: int, guild_id: int) -> str:
        account = self._required_account(owner_id)
        _require_scope(account, "guilds.join")

        self._request_json(
            "PUT",
            f"/guilds/{guild_id}/members/{account.discord_user_id}",
            headers={
                "Authorization": f"Bot {self.settings.discord.token}",
                "Content-Type": "application/json",
            },
            json={"access_token": account.access_token},
            expected_statuses=(201, 204),
        )
        self.database.log_event("guild_joined", owner_id, str(guild_id))
        return "The linked account was added, or was already in this server."

    def send_webhook_message(
        self,
        owner_id: int,
        content: str,
        username: str | None = None,
    ) -> str:
        account = self._required_account(owner_id)
        _require_scope(account, "webhook.incoming")
        if not account.has_webhook:
            raise DiscordApiError("No OAuth webhook was stored for this account.", 404)

        payload = {"content": content.strip()}
        if username and username.strip():
            payload["username"] = username.strip()[:80]

        if not payload["content"]:
            raise DiscordApiError("Webhook message content cannot be empty.", 400)

        response = self._request_json(
            "POST",
            f"/webhooks/{account.webhook_id}/{account.webhook_token}",
            headers={"Content-Type": "application/json"},
            params={"wait": "true"},
            json=payload,
            expected_statuses=(200, 204),
        )
        message_id = response.get("id") if isinstance(response, dict) else None
        details = str(message_id or account.webhook_channel_id or account.webhook_id)
        self.database.log_event("webhook_message_sent", owner_id, details)
        if message_id:
            return f"Webhook message sent. Message ID: `{message_id}`"
        return "Webhook message sent."

    def fetch_entitlements(self, owner_id: int) -> list[dict[str, Any]]:
        account = self._required_account(owner_id)
        _require_scope(account, "applications.entitlements")
        payload = self._request_json(
            "GET",
            f"/applications/{self.settings.discord.client_id}/entitlements",
            headers=_bearer_headers(account.access_token),
            params={
                "user_id": account.discord_user_id,
                "limit": "25",
                "exclude_deleted": "false",
            },
        )
        if isinstance(payload, list):
            return payload
        raise DiscordApiError("Discord returned an unexpected entitlement list.", 502)

    def fetch_role_connection(self, owner_id: int) -> dict[str, Any]:
        account = self._required_account(owner_id)
        _require_scope(account, "role_connections.write")
        payload = self._request_json(
            "GET",
            f"/users/@me/applications/{self.settings.discord.client_id}/role-connection",
            headers=_bearer_headers(account.access_token),
        )
        if isinstance(payload, dict):
            return payload
        raise DiscordApiError("Discord returned an unexpected role connection.", 502)

    def update_role_connection(
        self,
        owner_id: int,
        platform_name: str | None,
        platform_username: str | None,
        metadata: dict[str, str],
    ) -> dict[str, Any]:
        account = self._required_account(owner_id)
        _require_scope(account, "role_connections.write")
        payload: dict[str, Any] = {"metadata": metadata}
        if platform_name:
            payload["platform_name"] = platform_name[:50]
        if platform_username:
            payload["platform_username"] = platform_username[:100]

        response = self._request_json(
            "PUT",
            f"/users/@me/applications/{self.settings.discord.client_id}/role-connection",
            headers={
                **_bearer_headers(account.access_token),
                "Content-Type": "application/json",
            },
            json=payload,
        )
        if isinstance(response, dict):
            self.database.log_event("role_connection_updated", owner_id, account.discord_user_id)
            return response
        raise DiscordApiError("Discord returned an unexpected role connection.", 502)

    def _required_account(self, owner_id: int) -> OAuthAccount:
        account = self.get_account(owner_id, refresh_if_needed=True)
        if account is None:
            raise DiscordApiError("No linked OAuth account was found.", 404)
        return account

    def _exchange_code(self, code: str) -> dict[str, Any]:
        return self._request_json(
            "POST",
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.settings.web.redirect_uri,
            },
            auth=(
                self.settings.discord.client_id,
                self.settings.discord.client_secret,
            ),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def _refresh_token(self, refresh_token: str) -> dict[str, Any]:
        return self._request_json(
            "POST",
            "/oauth2/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            auth=(
                self.settings.discord.client_id,
                self.settings.discord.client_secret,
            ),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    def _revoke_token(self, token: str) -> None:
        self._request_json(
            "POST",
            "/oauth2/token/revoke",
            data={"token": token},
            auth=(
                self.settings.discord.client_id,
                self.settings.discord.client_secret,
            ),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            expected_statuses=(200, 204),
        )

    def _request_json(
        self,
        method: str,
        path: str,
        expected_statuses: tuple[int, ...] = (200,),
        **kwargs: Any,
    ) -> Any:
        url = path if path.startswith("http") else f"{API_BASE_URL}{path}"
        try:
            response = self.session.request(
                method,
                url,
                timeout=self.settings.oauth.request_timeout,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise DiscordApiError(f"Discord request failed: {exc}") from exc

        if response.status_code not in expected_statuses:
            raise DiscordApiError(
                _discord_error_message(response),
                400 if response.status_code < 500 else 502,
            )

        if response.status_code == 204 or not response.text:
            return {}

        try:
            return response.json()
        except ValueError as exc:
            raise DiscordApiError("Discord returned invalid JSON.", 502) from exc


def normalize_scopes(scopes: list[str]) -> list[str]:
    cleaned = []
    for scope in [*scopes, "identify"]:
        scope = str(scope).strip()
        if scope and scope not in cleaned:
            cleaned.append(scope)
    return cleaned


def _bearer_headers(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


def _required(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not value:
        raise DiscordApiError(f"Discord did not return {key}.", 502)
    return str(value)


def _webhook_fields(
    webhook: Any,
    fallback: OAuthAccount | None = None,
) -> dict[str, str | None]:
    if not isinstance(webhook, dict):
        return {
            "webhook_id": fallback.webhook_id if fallback else None,
            "webhook_token": fallback.webhook_token if fallback else None,
            "webhook_channel_id": fallback.webhook_channel_id if fallback else None,
            "webhook_guild_id": fallback.webhook_guild_id if fallback else None,
            "webhook_name": fallback.webhook_name if fallback else None,
        }

    return {
        "webhook_id": _optional_string(webhook.get("id")),
        "webhook_token": _optional_string(webhook.get("token")),
        "webhook_channel_id": _optional_string(webhook.get("channel_id")),
        "webhook_guild_id": _optional_string(webhook.get("guild_id")),
        "webhook_name": _optional_string(webhook.get("name")),
    }


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _require_scope(account: OAuthAccount, scope: str) -> None:
    if not account.has_scope(scope):
        raise DiscordApiError(f"The linked account is missing the {scope} scope.", 403)


def _discord_error_message(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text[:300] or f"Discord returned HTTP {response.status_code}."

    if isinstance(payload, dict):
        return str(
            payload.get("error_description")
            or payload.get("message")
            or payload.get("error")
            or f"Discord returned HTTP {response.status_code}."
        )
    return f"Discord returned HTTP {response.status_code}."
