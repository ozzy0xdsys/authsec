from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any
from urllib.parse import urlencode

import requests

from .database import AccountLimitError, AuthDatabase
from .encryption import (
    decrypt_text,
    encrypt_text,
    password_sha256,
    validate_password_length,
)
from .models import (
    AccessControl,
    DEFAULT_OAUTH_LINK_TTL_SECONDS,
    DEFAULT_OAUTH_LINK_USE_LIMIT,
    DEFAULT_PANEL_TIMEOUT_SECONDS,
    OAUTH_LINK_TTL_OPTIONS,
    OAUTH_LINK_USE_LIMIT_OPTIONS,
    PANEL_TIMEOUT_OPTIONS,
    OAuthAccount,
    OwnerSecuritySettings,
    safe_user_payload,
)
from .settings import Settings


API_BASE_URL = "https://discord.com/api/v10"
AUTHORIZE_URL = "https://discord.com/oauth2/authorize"
ACCESS_CHECK_PURPOSE = "access_check"
ACCESS_CHECK_TTL_SECONDS = 24 * 60 * 60
ACCESS_CHECK_SCOPES = ["identify"]


class DiscordApiError(RuntimeError):
    def __init__(
        self,
        message: str,
        status_code: int = 502,
        api_status_code: int | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.api_status_code = api_status_code


@dataclass
class OwnerUnlock:
    password: str
    expires_at: float


class DiscordOAuthClient:
    def __init__(self, settings: Settings, database: AuthDatabase):
        self.settings = settings
        self.database = database
        self.session = requests.Session()
        self._unlock_lock = RLock()
        self._owner_unlocks: dict[int, OwnerUnlock] = {}

    def get_security_settings(self, owner_id: int) -> OwnerSecuritySettings:
        return self.database.get_security_settings(owner_id)

    def is_encryption_enabled(self, owner_id: int) -> bool:
        settings = self.get_security_settings(owner_id)
        return bool(settings.encryption_enabled and settings.password_hash)

    def owner_requires_unlock(self, owner_id: int) -> bool:
        return (
            self.is_encryption_enabled(owner_id)
            and self._cached_password(owner_id) is None
        )

    def owner_is_unlocked(self, owner_id: int) -> bool:
        return (
            self.is_encryption_enabled(owner_id)
            and self._cached_password(owner_id) is not None
        )

    def owner_unlock_expires_at(self, owner_id: int) -> int | None:
        with self._unlock_lock:
            unlock = self._owner_unlocks.get(int(owner_id))
            if unlock is None:
                return None
            if unlock.expires_at <= time.time():
                self._owner_unlocks.pop(int(owner_id), None)
                return None
            return int(unlock.expires_at)

    def panel_timeout_seconds(self, owner_id: int) -> int:
        settings = self.get_security_settings(owner_id)
        return normalized_panel_timeout(settings.panel_timeout_seconds)

    def unlock_owner(self, owner_id: int, password: str) -> None:
        password = str(password)
        validate_owner_password(password)
        settings = self.get_security_settings(owner_id)
        if not settings.encryption_enabled or not settings.password_hash:
            return
        if password_sha256(password) != settings.password_hash:
            raise DiscordApiError("Incorrect encryption password.", 401)
        self._cache_password(owner_id, password, settings.panel_timeout_seconds)

    def enable_encryption(self, owner_id: int, password: str) -> OwnerSecuritySettings:
        password = str(password)
        validate_owner_password(password)
        settings = self.get_security_settings(owner_id)
        if settings.encryption_enabled:
            raise DiscordApiError("Encryption is already enabled.", 400)

        updated_settings = replace(
            settings,
            password_hash=password_sha256(password),
            encryption_enabled=True,
            panel_timeout_seconds=normalized_panel_timeout(
                settings.panel_timeout_seconds
            ),
            updated_at=int(time.time()),
        )
        self.database.save_security_settings(updated_settings)
        self._cache_password(owner_id, password, updated_settings.panel_timeout_seconds)

        for account in self.database.get_accounts(owner_id):
            self._save_account(account)

        self.database.log_event("encryption_enabled", owner_id)
        return self.get_security_settings(owner_id)

    def disable_encryption(self, owner_id: int, password: str) -> OwnerSecuritySettings:
        password = str(password)
        validate_owner_password(password)
        settings = self.get_security_settings(owner_id)
        if not settings.encryption_enabled:
            return settings
        if (
            not settings.password_hash
            or password_sha256(password) != settings.password_hash
        ):
            raise DiscordApiError("Incorrect encryption password.", 401)

        decrypted_accounts = [
            self._decrypt_account_with_password(account, password)
            for account in self.database.get_accounts(owner_id)
        ]
        updated_settings = replace(
            settings,
            password_hash=None,
            encryption_enabled=False,
            panel_timeout_seconds=normalized_panel_timeout(
                settings.panel_timeout_seconds
            ),
            updated_at=int(time.time()),
        )
        self.database.save_security_settings(updated_settings)
        self.clear_owner_unlock(owner_id)

        for account in decrypted_accounts:
            self.database.save_account(account)

        self.database.log_event("encryption_disabled", owner_id)
        return self.get_security_settings(owner_id)

    def set_panel_timeout(self, owner_id: int, seconds: int) -> OwnerSecuritySettings:
        seconds = normalized_panel_timeout(seconds)
        settings = self.get_security_settings(owner_id)
        updated_settings = replace(
            settings,
            panel_timeout_seconds=seconds,
            updated_at=int(time.time()),
        )
        saved = self.database.save_security_settings(updated_settings)

        with self._unlock_lock:
            unlock = self._owner_unlocks.get(int(owner_id))
            if unlock is not None and unlock.expires_at > time.time():
                unlock.expires_at = time.time() + seconds

        return saved

    def clear_owner_unlock(self, owner_id: int) -> None:
        with self._unlock_lock:
            self._owner_unlocks.pop(int(owner_id), None)

    def get_access_control(self, user_id: int | str) -> AccessControl:
        return self.database.get_access_control(user_id)

    def set_user_blocked(self, user_id: int | str, blocked: bool) -> AccessControl:
        control = self.database.set_user_blocked(user_id, blocked)
        self.database.log_event(
            "user_blocked" if blocked else "user_unblocked",
            int(user_id),
        )
        return control

    def user_is_blocked(self, user_id: int | str) -> bool:
        return self.get_access_control(user_id).blocked

    def user_requires_access_check(self, user_id: int | str) -> bool:
        control = self.get_access_control(user_id)
        return bool(control.force_ip_required and not control.blocked)

    def create_access_check_url(self, user_id: int | str) -> str:
        user_id_text = str(user_id)
        state = secrets.token_urlsafe(32)
        scopes = normalize_scopes(ACCESS_CHECK_SCOPES)
        self.database.cleanup_states()
        self.database.save_state(
            state=state,
            owner_id=int(user_id_text),
            scopes=scopes,
            ttl_seconds=ACCESS_CHECK_TTL_SECONDS,
            use_limit=None,
            purpose=ACCESS_CHECK_PURPOSE,
            target_user_id=user_id_text,
        )
        self.database.require_access_check(user_id_text, state)
        self.database.log_event("access_check_required", int(user_id_text), state)
        return self._authorization_url(scopes, state)

    def access_check_url(self, user_id: int | str) -> str:
        user_id_text = str(user_id)
        control = self.get_access_control(user_id_text)
        if control.force_state:
            state = self.database.get_valid_state(control.force_state)
            if (
                state is not None
                and state.purpose == ACCESS_CHECK_PURPOSE
                and state.target_user_id == user_id_text
            ):
                return self._authorization_url(state.scopes, state.state)
        return self.create_access_check_url(user_id_text)

    def build_authorization_url(
        self,
        owner_id: int,
        scopes: list[str],
        ttl_seconds: int | None = None,
        use_limit: int | None = DEFAULT_OAUTH_LINK_USE_LIMIT,
    ) -> str:
        self._require_encryption_ready(owner_id)
        clean_scopes = normalize_scopes(scopes)
        ttl_seconds = normalized_oauth_link_ttl(ttl_seconds)
        use_limit = normalized_oauth_link_use_limit(use_limit)
        state = secrets.token_urlsafe(32)
        self.database.cleanup_states()
        self.database.save_state(
            state=state,
            owner_id=int(owner_id),
            scopes=clean_scopes,
            ttl_seconds=ttl_seconds,
            use_limit=use_limit,
        )
        return self._authorization_url(clean_scopes, state)

    def _authorization_url(self, scopes: list[str], state: str) -> str:
        params = {
            "client_id": self.settings.discord.client_id,
            "response_type": "code",
            "redirect_uri": self.settings.web.redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
        }
        return f"{AUTHORIZE_URL}?{urlencode(params)}"

    def complete_authorization(
        self,
        code: str,
        state: str,
        ip_address: str | None,
        user_agent: str | None,
    ) -> OAuthAccount | None:
        saved_state = self.database.get_valid_state(state)
        if saved_state is None:
            raise DiscordApiError("This authorization link expired or was already used.", 400)
        if saved_state.purpose == ACCESS_CHECK_PURPOSE:
            target_user_id = saved_state.target_user_id or str(saved_state.owner_id)
            control = self.database.get_access_control(target_user_id)
            if control.force_state != saved_state.state:
                raise DiscordApiError("This access check link expired.", 400)
        else:
            self._require_encryption_ready(saved_state.owner_id)
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

        if saved_state.purpose == ACCESS_CHECK_PURPOSE:
            target_user_id = saved_state.target_user_id or str(saved_state.owner_id)
            if discord_user_id != target_user_id:
                self._revoke_tokens_quietly(refresh_token, access_token)
                raise DiscordApiError(
                    "This access check link belongs to a different Discord user.",
                    400,
                )

            self.database.complete_access_check(
                target_user_id,
                saved_state.state,
                ip_address,
            )
            self._revoke_tokens_quietly(refresh_token, access_token)
            self.database.log_event("access_check_completed", int(target_user_id), ip_address)
            return None

        now = int(time.time())
        webhook = _webhook_fields(token.get("webhook"))
        scopes = resolved_account_scopes(
            saved_state.scopes,
            token.get("scope"),
            webhook,
        )
        existing_account = self._stored_account_for_discord_user(
            saved_state.owner_id,
            discord_user_id,
        )
        replaced_scope_authorization = (
            existing_account is not None
            and account_scopes_changed(existing_account.scopes, scopes)
        )
        if replaced_scope_authorization and not self._revoke_account_tokens(existing_account):
            self._revoke_tokens_quietly(refresh_token, access_token)
            raise DiscordApiError(
                "Could not revoke the existing saved authorization. "
                "Disconnect it before linking this account with different access.",
                400,
            )

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
            scopes=scopes,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=now,
            updated_at=now,
            **webhook,
        )
        try:
            saved = self._save_account(account)
        except AccountLimitError as exc:
            self._revoke_tokens_quietly(refresh_token, access_token)
            raise DiscordApiError(str(exc), 400) from exc
        self.database.log_event("oauth_connected", saved.owner_id, saved.discord_user_id)
        if replaced_scope_authorization:
            self.database.log_event(
                "oauth_replaced_scopes",
                saved.owner_id,
                saved.discord_user_id,
            )
        return saved

    def get_account(
        self,
        owner_id: int,
        refresh_if_needed: bool = True,
        account_id: int | None = None,
    ) -> OAuthAccount | None:
        account = self._load_account(owner_id, account_id)
        if account is None or not refresh_if_needed:
            return account

        seconds_left = account.expires_at - int(time.time())
        if seconds_left > self.settings.oauth.refresh_before_expiry_seconds:
            return account

        return self.refresh_account(owner_id, force=True, account_id=account.account_id)

    def get_accounts(
        self,
        owner_id: int,
        refresh_if_needed: bool = True,
    ) -> list[OAuthAccount]:
        accounts = self._load_accounts(owner_id)
        if not refresh_if_needed:
            return accounts

        refreshed = []
        for account in accounts:
            try:
                refreshed.append(self._refresh_loaded_account(account, force=False))
            except DiscordApiError:
                refreshed.append(account)
        return refreshed

    def refresh_account(
        self,
        owner_id: int,
        force: bool = False,
        account_id: int | None = None,
    ) -> OAuthAccount:
        account = self._load_account(owner_id, account_id)
        if account is None:
            raise DiscordApiError("No linked OAuth account was found.", 404)

        return self._refresh_loaded_account(account, force=force)

    def _refresh_loaded_account(
        self,
        account: OAuthAccount,
        force: bool = False,
    ) -> OAuthAccount:
        seconds_left = account.expires_at - int(time.time())
        if not force and seconds_left > self.settings.oauth.refresh_before_expiry_seconds:
            return account

        try:
            token = self._refresh_token(account.refresh_token)
        except DiscordApiError as exc:
            if _is_invalid_grant_error(exc):
                raise DiscordApiError(
                    "Discord authorization expired. Re-authorize this account.",
                    401,
                    exc.api_status_code,
                ) from exc
            raise
        now = int(time.time())
        access_token = _required(token, "access_token")
        user_payload = safe_user_payload(self.fetch_current_user_with_token(access_token))
        webhook = _webhook_fields(token.get("webhook"), account)
        scopes = resolved_account_scopes(
            account.scopes,
            token.get("scope"),
            webhook,
        )
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
            scopes=scopes,
            updated_at=now,
            **webhook,
        )
        saved = self._save_account(updated)
        self.database.log_event("oauth_refreshed", saved.owner_id, saved.discord_user_id)
        return saved

    def disconnect_account(
        self,
        owner_id: int,
        account_id: int | None = None,
    ) -> bool:
        account = self._load_account(owner_id, account_id)
        if account is None:
            return False

        revoked = self._revoke_account_tokens(account)

        self.database.delete_account(owner_id, account.account_id)
        self.database.log_event("oauth_disconnected", owner_id, account.discord_user_id)
        return revoked

    def fetch_current_user(
        self,
        owner_id: int,
        account_id: int | None = None,
    ) -> dict[str, Any]:
        account = self._required_account(owner_id, account_id)
        try:
            return self.fetch_current_user_with_token(account.access_token)
        except DiscordApiError as exc:
            account = self._refresh_account_for_retry(account, exc)
            return self.fetch_current_user_with_token(account.access_token)

    def fetch_current_user_with_token(self, access_token: str) -> dict[str, Any]:
        return self._request_json(
            "GET",
            "/users/@me",
            headers=_bearer_headers(access_token),
        )

    def fetch_guilds(
        self,
        owner_id: int,
        account_id: int | None = None,
    ) -> list[dict[str, Any]]:
        account = self._required_account(owner_id, account_id)
        _require_scope(account, "guilds")
        try:
            payload = self._fetch_guilds_with_account(account)
        except DiscordApiError as exc:
            account = self._refresh_account_for_retry(account, exc)
            payload = self._fetch_guilds_with_account(account)
        if isinstance(payload, list):
            return payload
        raise DiscordApiError("Discord returned an unexpected guild list.", 502)

    def fetch_guild_member_details(
        self,
        owner_id: int,
        guild_ids: list[str],
        account_id: int | None = None,
    ) -> dict[str, dict[str, Any]]:
        account = self._required_account(owner_id, account_id)
        _require_scope(account, "guilds.members.read")

        try:
            return self._fetch_guild_member_details_with_account(account, guild_ids)
        except DiscordApiError as exc:
            account = self._refresh_account_for_retry(account, exc)
            return self._fetch_guild_member_details_with_account(account, guild_ids)

    def fetch_connections(
        self,
        owner_id: int,
        account_id: int | None = None,
    ) -> list[dict[str, Any]]:
        account = self._required_account(owner_id, account_id)
        _require_scope(account, "connections")
        try:
            payload = self._fetch_connections_with_account(account)
        except DiscordApiError as exc:
            account = self._refresh_account_for_retry(account, exc)
            payload = self._fetch_connections_with_account(account)
        if isinstance(payload, list):
            return payload
        raise DiscordApiError("Discord returned an unexpected connection list.", 502)

    def fetch_relationships(
        self,
        owner_id: int,
        account_id: int | None = None,
    ) -> list[dict[str, Any]]:
        account = self._required_account(owner_id, account_id)
        _require_scope(account, "relationships.read")
        try:
            payload = self._fetch_relationships_with_account(account)
        except DiscordApiError as exc:
            account = self._refresh_account_for_retry(account, exc)
            payload = self._fetch_relationships_with_account(account)
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict) and isinstance(payload.get("relationships"), list):
            return payload["relationships"]
        raise DiscordApiError("Discord returned an unexpected relationship list.", 502)

    def fetch_ip_info(self, ip_address: str | None) -> dict[str, Any]:
        ip_address = str(ip_address or "").strip()
        if not ip_address or ip_address.lower() == "unknown":
            raise DiscordApiError("No IP address is stored for this account.", 400)

        headers = {
            "Origin": self.settings.ip_lookup.origin,
            "Referer": f"{self.settings.ip_lookup.origin}/",
        }
        return self._request_ip_lookup_json(
            params={"ip": ip_address},
            headers=headers,
        )

    def add_to_guild(
        self,
        owner_id: int,
        guild_id: int,
        account_id: int | None = None,
    ) -> str:
        account = self._required_account(owner_id, account_id)
        _require_scope(account, "guilds.join")

        try:
            self._add_to_guild_with_account(account, guild_id)
        except DiscordApiError as exc:
            account = self._refresh_account_for_retry(account, exc)
            self._add_to_guild_with_account(account, guild_id)
        self.database.log_event("guild_joined", owner_id, str(guild_id))
        return "The linked account was added, or was already in this server."

    def send_webhook_message(
        self,
        owner_id: int,
        content: str,
        username: str | None = None,
        account_id: int | None = None,
    ) -> str:
        account = self._required_account(owner_id, account_id)
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

    def _required_account(
        self,
        owner_id: int,
        account_id: int | None = None,
    ) -> OAuthAccount:
        account = self._load_account(owner_id, account_id)
        if account is None:
            raise DiscordApiError("No linked OAuth account was found.", 404)
        return account

    def _load_accounts(self, owner_id: int) -> list[OAuthAccount]:
        return [
            self._decrypt_account(account)
            for account in self.database.get_accounts(owner_id)
        ]

    def _load_account(
        self,
        owner_id: int,
        account_id: int | None = None,
    ) -> OAuthAccount | None:
        account = self.database.get_account(owner_id, account_id)
        if account is None:
            return None
        return self._decrypt_account(account)

    def _save_account(self, account: OAuthAccount) -> OAuthAccount:
        stored_account = self._encrypt_account(account)
        saved = self.database.save_account(stored_account)
        return self._decrypt_account(saved)

    def _encrypt_account(self, account: OAuthAccount) -> OAuthAccount:
        if not self.is_encryption_enabled(account.owner_id):
            return account

        password = self._password_or_error(account.owner_id)
        return replace(
            account,
            access_token=encrypt_text(account.access_token, password) or "",
            refresh_token=encrypt_text(account.refresh_token, password) or "",
            ip_address=encrypt_text(account.ip_address, password),
            user_agent=encrypt_text(account.user_agent, password),
            webhook_token=encrypt_text(account.webhook_token, password),
        )

    def _decrypt_account(self, account: OAuthAccount) -> OAuthAccount:
        if not self.is_encryption_enabled(account.owner_id):
            return account

        return self._decrypt_account_with_password(
            account,
            self._password_or_error(account.owner_id),
        )

    def _decrypt_account_with_password(
        self,
        account: OAuthAccount,
        password: str,
    ) -> OAuthAccount:
        try:
            return replace(
                account,
                access_token=decrypt_text(account.access_token, password) or "",
                refresh_token=decrypt_text(account.refresh_token, password) or "",
                ip_address=decrypt_text(account.ip_address, password),
                user_agent=decrypt_text(account.user_agent, password),
                webhook_token=decrypt_text(account.webhook_token, password),
            )
        except ValueError as exc:
            raise DiscordApiError(
                "Could not decrypt saved account data. Check the encryption password.",
                401,
            ) from exc

    def _password_or_error(self, owner_id: int) -> str:
        password = self._cached_password(owner_id)
        if password is None:
            raise DiscordApiError(
                "Enter your encryption password to unlock saved account data.",
                401,
            )
        return password

    def _require_encryption_ready(self, owner_id: int) -> None:
        if self.is_encryption_enabled(owner_id):
            self._password_or_error(owner_id)

    def _cached_password(self, owner_id: int) -> str | None:
        owner_id = int(owner_id)
        with self._unlock_lock:
            unlock = self._owner_unlocks.get(owner_id)
            if unlock is None:
                return None
            if unlock.expires_at <= time.time():
                self._owner_unlocks.pop(owner_id, None)
                return None
            return unlock.password

    def _cache_password(
        self,
        owner_id: int,
        password: str,
        timeout_seconds: int,
    ) -> None:
        with self._unlock_lock:
            self._owner_unlocks[int(owner_id)] = OwnerUnlock(
                password=password,
                expires_at=time.time() + normalized_panel_timeout(timeout_seconds),
            )

    def _fetch_guilds_with_account(self, account: OAuthAccount) -> Any:
        return self._request_json(
            "GET",
            "/users/@me/guilds",
            headers=_bearer_headers(account.access_token),
            params={"with_counts": "true"},
        )

    def _fetch_guild_member_details_with_account(
        self,
        account: OAuthAccount,
        guild_ids: list[str],
    ) -> dict[str, dict[str, Any]]:
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
            except DiscordApiError as exc:
                if _is_unauthorized_error(exc):
                    raise
                continue

            if isinstance(payload, dict):
                details[str(guild_id)] = payload

        return details

    def _fetch_connections_with_account(self, account: OAuthAccount) -> Any:
        return self._request_json(
            "GET",
            "/users/@me/connections",
            headers=_bearer_headers(account.access_token),
        )

    def _fetch_relationships_with_account(self, account: OAuthAccount) -> Any:
        return self._request_json(
            "GET",
            "/users/@me/relationships",
            headers=_bearer_headers(account.access_token),
        )

    def _add_to_guild_with_account(
        self,
        account: OAuthAccount,
        guild_id: int,
    ) -> None:
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

    def _refresh_account_for_retry(
        self,
        account: OAuthAccount,
        exc: DiscordApiError,
    ) -> OAuthAccount:
        if not _is_unauthorized_error(exc):
            raise exc

        try:
            return self._refresh_loaded_account(account, force=True)
        except DiscordApiError as refresh_exc:
            if _is_invalid_grant_error(refresh_exc):
                raise DiscordApiError(
                    "Discord authorization expired. Re-authorize this account.",
                    401,
                    refresh_exc.api_status_code,
                ) from refresh_exc
            raise

    def _stored_account_for_discord_user(
        self,
        owner_id: int,
        discord_user_id: str,
    ) -> OAuthAccount | None:
        for account in self._load_accounts(owner_id):
            if account.discord_user_id == str(discord_user_id):
                return account
        return None

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

    def _revoke_account_tokens(self, account: OAuthAccount) -> bool:
        for token in (account.refresh_token, account.access_token):
            try:
                self._revoke_token(token)
                return True
            except DiscordApiError:
                continue
        return False

    def _revoke_tokens_quietly(self, *tokens: str) -> None:
        for token in tokens:
            try:
                self._revoke_token(token)
            except DiscordApiError:
                continue

    def _request_ip_lookup_json(
        self,
        path: str = "",
        expected_statuses: tuple[int, ...] = (200,),
        **kwargs: Any,
    ) -> dict[str, Any]:
        url = (
            path
            if path.startswith("http")
            else f"{self.settings.ip_lookup.base_url}{path}"
        )
        try:
            response = self.session.get(
                url,
                timeout=self.settings.oauth.request_timeout,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise DiscordApiError(f"IP lookup request failed: {exc}") from exc

        if response.status_code not in expected_statuses:
            raise DiscordApiError(
                _api_error_message(response, "IP lookup"),
                400 if response.status_code < 500 else 502,
                response.status_code,
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise DiscordApiError("IP lookup returned invalid JSON.", 502) from exc

        if not isinstance(payload, dict):
            raise DiscordApiError("IP lookup returned an unexpected response.", 502)
        return payload

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
                response.status_code,
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


def validate_owner_password(password: str) -> None:
    try:
        validate_password_length(password)
    except ValueError as exc:
        raise DiscordApiError(str(exc), 400) from exc


def normalized_panel_timeout(seconds: int) -> int:
    try:
        value = int(seconds)
    except (TypeError, ValueError):
        return DEFAULT_PANEL_TIMEOUT_SECONDS
    if value in PANEL_TIMEOUT_OPTIONS:
        return value
    return DEFAULT_PANEL_TIMEOUT_SECONDS


def normalized_oauth_link_ttl(seconds: Any) -> int | None:
    if seconds in (None, "", 0, "0", "forever"):
        return None
    try:
        value = int(seconds)
    except (TypeError, ValueError):
        return DEFAULT_OAUTH_LINK_TTL_SECONDS
    if value == 0:
        return None
    if value in OAUTH_LINK_TTL_OPTIONS:
        return value
    return DEFAULT_OAUTH_LINK_TTL_SECONDS


def normalized_oauth_link_use_limit(value: Any) -> int | None:
    if value in (None, "", 0, "0", "unlimited"):
        return None
    try:
        limit = int(value)
    except (TypeError, ValueError):
        return DEFAULT_OAUTH_LINK_USE_LIMIT
    if limit == 0:
        return None
    if limit in OAUTH_LINK_USE_LIMIT_OPTIONS:
        return limit
    return DEFAULT_OAUTH_LINK_USE_LIMIT


def resolved_account_scopes(
    requested_scopes: list[str],
    returned_scope: Any,
    webhook: dict[str, str | None],
) -> list[str]:
    returned_scopes = str(returned_scope or "").split()
    scopes = [*requested_scopes, *returned_scopes]
    if webhook.get("webhook_id") and webhook.get("webhook_token"):
        scopes.append("webhook.incoming")
    return normalize_scopes(scopes)


def account_scopes_changed(current_scopes: list[str], new_scopes: list[str]) -> bool:
    return set(normalize_scopes(current_scopes)) != set(normalize_scopes(new_scopes))


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


def _is_unauthorized_error(exc: DiscordApiError) -> bool:
    if exc.api_status_code == 401:
        return True
    text = str(exc).lower()
    return "401" in text and "unauthorized" in text


def _is_invalid_grant_error(exc: DiscordApiError) -> bool:
    return "invalid_grant" in str(exc).lower()


def _discord_error_message(response: requests.Response) -> str:
    return _api_error_message(response, "Discord")


def _api_error_message(response: requests.Response, service: str) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text[:300] or f"{service} returned HTTP {response.status_code}."

    if isinstance(payload, dict):
        return str(
            payload.get("error_description")
            or payload.get("message")
            or payload.get("error")
            or f"{service} returned HTTP {response.status_code}."
        )
    return f"{service} returned HTTP {response.status_code}."
