from __future__ import annotations

import html
import secrets
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

import discord
from flask import Flask, Response, jsonify, redirect, request, session, url_for

from .bot import BotRuntime
from .models import MAX_ACCOUNTS_PER_OWNER, OAuthAccount
from .oauth import AUTHORIZE_URL, DiscordApiError, DiscordOAuthClient


PAGE_SIZE_CONNECTIONS = 15
PAGE_SIZE_GUILDS = 10
PAGE_SIZE_RELATIONSHIPS = 10
DEFAULT_WEB_SETUP_SCOPES = {
    "email",
    "guilds",
    "connections",
    "relationships.read",
}
WEB_SCOPE_LABELS = {
    "email": "Email",
    "guilds": "Guilds",
    "connections": "Connections",
    "relationships.read": "Relationships",
    "guilds.members.read": "Guild Join Dates",
    "guilds.join": "Join Guilds",
    "webhook.incoming": "Incoming Webhook",
    "applications.builds.read": "App Builds",
    "gdm.join": "Group DM Join",
}


def create_web_app(oauth_client: DiscordOAuthClient, bot_runtime: BotRuntime) -> Flask:
    app = Flask(__name__)
    settings = oauth_client.settings
    app.secret_key = settings.web.session_secret or secrets.token_urlsafe(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    @app.before_request
    def force_https():
        if not settings.web.force_https or _is_local_request():
            return None

        forwarded_proto = request.headers.get("X-Forwarded-Proto")
        if request.is_secure or forwarded_proto == "https":
            return None

        return redirect(request.url.replace("http://", "https://", 1), code=301)

    @app.get("/")
    def home():
        user = _session_user()
        if user is None:
            return _page_response("AuthSec", _login_panel())

        return _dashboard_response(oauth_client, user)

    @app.get("/login")
    def login():
        state = secrets.token_urlsafe(32)
        session["web_login_state"] = state
        params = {
            "client_id": settings.discord.client_id,
            "response_type": "code",
            "redirect_uri": settings.web.redirect_uri,
            "scope": "identify",
            "state": state,
        }
        return redirect(f"{AUTHORIZE_URL}?{urlencode(params)}")

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("home"))

    @app.post("/authorize")
    def authorize_account():
        user = _require_session_user()
        if user is None:
            return redirect(url_for("home"))
        if not _valid_csrf():
            _set_notice("Session check failed. Try again.", "error")
            return redirect(url_for("home"))

        selected_scopes = [
            scope
            for scope in request.form.getlist("scopes")
            if scope in WEB_SCOPE_LABELS
        ]
        if not selected_scopes:
            selected_scopes = list(DEFAULT_WEB_SETUP_SCOPES)

        authorization_url = oauth_client.build_authorization_url(
            _owner_id(user),
            selected_scopes,
        )
        if _wants_authorize_json():
            return jsonify({"url": authorization_url})

        return redirect(authorization_url)

    @app.get("/health")
    def health():
        return jsonify({"ok": True})

    @app.get("/callback")
    def callback():
        code = request.args.get("code")
        state = request.args.get("state")

        if not code or not state:
            return _page(
                "Authorization failed",
                "Discord did not send the expected code and state values.",
                400,
            )

        if _is_web_login_state(state):
            try:
                discord_user = oauth_client.complete_web_login(code)
            except DiscordApiError as exc:
                session.pop("web_login_state", None)
                return _page("Authorization failed", str(exc), exc.status_code)

            session.pop("web_login_state", None)
            session["web_user"] = _web_user_session_payload(discord_user)
            return redirect(url_for("home"))

        try:
            account = oauth_client.complete_authorization(
                code=code,
                state=state,
                ip_address=_client_ip(),
                user_agent=_user_agent(),
            )
        except DiscordApiError as exc:
            return _page("Authorization failed", str(exc), exc.status_code)

        bot_runtime.notify_linked_account(account)
        return _close_tab_page()

    @app.get("/account/<int:account_id>")
    def account_overview(account_id: int):
        user = _require_session_user()
        if user is None:
            return redirect(url_for("home"))

        return _dashboard_response(oauth_client, user, selected_account_id=account_id)

    @app.get("/account/<int:account_id>/details")
    def account_details(account_id: int):
        user = _require_session_user()
        if user is None:
            return redirect(url_for("home"))

        owner_id = _owner_id(user)
        account = oauth_client.get_account(owner_id, False, account_id)
        if account is None:
            _set_notice("That saved account was not found.", "error")
            return redirect(url_for("home"))

        try:
            payload = oauth_client.fetch_current_user(owner_id, account_id)
            content = _details_panel(account, payload)
        except DiscordApiError as exc:
            content = _error_panel(str(exc))

        return _dashboard_response(oauth_client, user, account_id, content)

    @app.get("/account/<int:account_id>/guilds")
    def account_guilds(account_id: int):
        user = _require_session_user()
        if user is None:
            return redirect(url_for("home"))

        owner_id = _owner_id(user)
        account = oauth_client.get_account(owner_id, False, account_id)
        if account is None:
            _set_notice("That saved account was not found.", "error")
            return redirect(url_for("home"))

        page = _page_number()
        try:
            guilds = oauth_client.fetch_guilds(owner_id, account_id)
            items, page, total_pages = _page_items(guilds, page, PAGE_SIZE_GUILDS)
            member_details = {}
            if account.has_scope("guilds.members.read"):
                guild_ids = [
                    str(guild.get("id"))
                    for guild in items
                    if guild.get("id") is not None
                ]
                member_details = oauth_client.fetch_guild_member_details(
                    owner_id,
                    guild_ids,
                    account_id,
                )
            content = _guilds_panel(account, items, page, total_pages, member_details)
        except DiscordApiError as exc:
            content = _error_panel(str(exc))

        return _dashboard_response(oauth_client, user, account_id, content)

    @app.get("/account/<int:account_id>/connections")
    def account_connections(account_id: int):
        user = _require_session_user()
        if user is None:
            return redirect(url_for("home"))

        owner_id = _owner_id(user)
        account = oauth_client.get_account(owner_id, False, account_id)
        if account is None:
            _set_notice("That saved account was not found.", "error")
            return redirect(url_for("home"))

        page = _page_number()
        try:
            connections = oauth_client.fetch_connections(owner_id, account_id)
            items, page, total_pages = _page_items(
                connections,
                page,
                PAGE_SIZE_CONNECTIONS,
            )
            content = _connections_panel(account, items, page, total_pages)
        except DiscordApiError as exc:
            content = _error_panel(str(exc))

        return _dashboard_response(oauth_client, user, account_id, content)

    @app.get("/account/<int:account_id>/relationships")
    def account_relationships(account_id: int):
        user = _require_session_user()
        if user is None:
            return redirect(url_for("home"))

        owner_id = _owner_id(user)
        account = oauth_client.get_account(owner_id, False, account_id)
        if account is None:
            _set_notice("That saved account was not found.", "error")
            return redirect(url_for("home"))

        page = _page_number()
        try:
            relationships = oauth_client.fetch_relationships(owner_id, account_id)
            items, page, total_pages = _page_items(
                relationships,
                page,
                PAGE_SIZE_RELATIONSHIPS,
            )
            content = _relationships_panel(account, items, page, total_pages)
        except DiscordApiError as exc:
            content = _error_panel(str(exc))

        return _dashboard_response(oauth_client, user, account_id, content)

    @app.get("/account/<int:account_id>/ip")
    def account_ip(account_id: int):
        user = _require_session_user()
        if user is None:
            return redirect(url_for("home"))

        owner_id = _owner_id(user)
        account = oauth_client.get_account(owner_id, False, account_id)
        if account is None:
            _set_notice("That saved account was not found.", "error")
            return redirect(url_for("home"))

        try:
            payload = oauth_client.fetch_ip_info(account.ip_address)
            content = _ip_panel(account, payload)
        except DiscordApiError as exc:
            content = _error_panel(str(exc))

        return _dashboard_response(oauth_client, user, account_id, content)

    @app.get("/account/<int:account_id>/webhook")
    def account_webhook(account_id: int):
        user = _require_session_user()
        if user is None:
            return redirect(url_for("home"))

        owner_id = _owner_id(user)
        account = oauth_client.get_account(owner_id, False, account_id)
        if account is None:
            _set_notice("That saved account was not found.", "error")
            return redirect(url_for("home"))

        return _dashboard_response(
            oauth_client,
            user,
            account_id,
            _webhook_panel(account),
        )

    @app.post("/account/<int:account_id>/refresh")
    def refresh_account(account_id: int):
        user = _require_session_user()
        if user is None:
            return redirect(url_for("home"))
        if not _valid_csrf():
            _set_notice("Session check failed. Try again.", "error")
            return redirect(url_for("account_overview", account_id=account_id))

        try:
            oauth_client.refresh_account(_owner_id(user), True, account_id)
            _set_notice("Account refreshed.", "success")
        except DiscordApiError as exc:
            _set_notice(str(exc), "error")
        return redirect(url_for("account_overview", account_id=account_id))

    @app.post("/account/<int:account_id>/disconnect")
    def disconnect_account(account_id: int):
        user = _require_session_user()
        if user is None:
            return redirect(url_for("home"))
        if not _valid_csrf():
            _set_notice("Session check failed. Try again.", "error")
            return redirect(url_for("account_overview", account_id=account_id))

        try:
            oauth_client.disconnect_account(_owner_id(user), account_id)
            _set_notice("Account disconnected.", "success")
        except DiscordApiError as exc:
            _set_notice(str(exc), "error")
        return redirect(url_for("home"))

    @app.post("/account/<int:account_id>/join")
    def join_guild(account_id: int):
        user = _require_session_user()
        if user is None:
            return redirect(url_for("home"))
        if not _valid_csrf():
            _set_notice("Session check failed. Try again.", "error")
            return redirect(url_for("account_overview", account_id=account_id))

        guild_id = str(request.form.get("guild_id") or "").strip()
        if not guild_id.isdigit():
            _set_notice("Enter a numeric guild ID.", "error")
            return redirect(url_for("account_overview", account_id=account_id))

        try:
            oauth_client.add_to_guild(_owner_id(user), int(guild_id), account_id)
            _set_notice("Guild join request sent.", "success")
        except DiscordApiError as exc:
            _set_notice(str(exc), "error")
        return redirect(url_for("account_overview", account_id=account_id))

    @app.post("/account/<int:account_id>/webhook")
    def send_webhook(account_id: int):
        user = _require_session_user()
        if user is None:
            return redirect(url_for("home"))
        if not _valid_csrf():
            _set_notice("Session check failed. Try again.", "error")
            return redirect(url_for("account_webhook", account_id=account_id))

        content = str(request.form.get("content") or "")
        username = str(request.form.get("username") or "").strip() or None
        try:
            oauth_client.send_webhook_message(
                _owner_id(user),
                content,
                username,
                account_id,
            )
            _set_notice("Webhook message sent.", "success")
        except DiscordApiError as exc:
            _set_notice(str(exc), "error")
        return redirect(url_for("account_webhook", account_id=account_id))

    return app


def _client_ip() -> str | None:
    for header in ("CF-Connecting-IP", "X-Real-IP"):
        value = request.headers.get(header)
        if value:
            return value.strip()

    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr


def _user_agent() -> str | None:
    value = request.headers.get("User-Agent")
    if not value:
        return None
    return value.strip()[:500] or None


def _is_local_request() -> bool:
    host = request.host.split(":", 1)[0].lower()
    return host in {"127.0.0.1", "localhost", "::1"}


def _wants_authorize_json() -> bool:
    accept = request.headers.get("Accept", "")
    return (
        request.headers.get("X-AuthSec-Copy-Link") == "1"
        or "application/json" in accept
    )


def _session_user() -> dict[str, Any] | None:
    user = session.get("web_user")
    if not isinstance(user, dict):
        return None
    if not user.get("id"):
        return None
    return user


def _require_session_user() -> dict[str, Any] | None:
    return _session_user()


def _owner_id(user: dict[str, Any]) -> int:
    return int(str(user["id"]))


def _is_web_login_state(state: str) -> bool:
    saved = session.get("web_login_state")
    return bool(
        isinstance(saved, str)
        and state
        and secrets.compare_digest(saved, state)
    )


def _web_user_session_payload(discord_user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(discord_user.get("id") or ""),
        "username": str(discord_user.get("username") or "unknown"),
        "global_name": discord_user.get("global_name"),
        "avatar": discord_user.get("avatar"),
    }


def _dashboard_response(
    oauth_client: DiscordOAuthClient,
    user: dict[str, Any],
    selected_account_id: int | None = None,
    content: str | None = None,
    status: int = 200,
) -> Response:
    owner_id = _owner_id(user)
    accounts = oauth_client.get_accounts(owner_id, True)
    selected = _selected_account(accounts, selected_account_id)
    if content is None:
        content = _overview_panel(selected)

    notice = _pop_notice()
    body = _dashboard_shell(user, accounts, selected, content, notice)
    return _page_response("AuthSec Panel", body, status)


def _selected_account(
    accounts: list[OAuthAccount],
    selected_account_id: int | None = None,
) -> OAuthAccount | None:
    if not accounts:
        return None

    for account in accounts:
        if selected_account_id is not None and account.account_id == selected_account_id:
            return account
    return accounts[0]


def _overview_panel(account: OAuthAccount | None) -> str:
    if account is None:
        return """
        <section class="workspace-panel">
          <div class="panel-head">
            <div>
              <p class="eyebrow">Accounts</p>
              <h1>No saved accounts</h1>
            </div>
          </div>
          <div class="empty-state">
            <p>Use the Discord bot setup flow to add an account.</p>
          </div>
        </section>
        """

    actions = _account_action_bar(account)
    joins = _join_guild_form(account)
    return f"""
    <section class="workspace-panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Selected Account</p>
          <h1>{_h(account.display_name)}</h1>
          <p class="subtle">ID {_code(account.discord_user_id)}</p>
        </div>
        <div class="status-pill">{_h(_mfa_text(account.mfa_enabled))}</div>
      </div>
      {_account_metrics(account)}
      {actions}
      <div class="split-grid">
        {_account_admin_forms(account)}
        {joins}
      </div>
    </section>
    """


def _details_panel(account: OAuthAccount, user: dict[str, Any]) -> str:
    fields = [
        ("Discord ID", _code(user.get("id") or account.discord_user_id)),
        ("Username", _h(user.get("username") or "unknown")),
        ("Display Name", _h(user.get("global_name") or "None")),
        ("Email", _h(user.get("email") or "None")),
        ("Verified", _h(_optional_bool(user.get("verified")))),
        ("MFA Enabled", _h(_optional_bool(user.get("mfa_enabled")))),
        ("IP Address", _code(account.ip_address or "unknown")),
        ("User Agent", _h(_truncate(account.user_agent or "unknown", 420))),
        ("Access", _h(_scope_list(account.scopes))),
        ("Token Expires", _h(_format_epoch(account.expires_at))),
        ("Last Updated", _h(_format_epoch(account.updated_at))),
    ]
    if account.has_scope("webhook.incoming"):
        fields.append(("OAuth Webhook", _h(_webhook_status(account))))

    return f"""
    <section class="workspace-panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">User Details</p>
          <h1>{_h(account.display_name)}</h1>
        </div>
        <img class="avatar large" src="{_h(_avatar_url(user))}" alt="">
      </div>
      {_field_grid(fields)}
      <div class="action-row">
        {_link_button(url_for("account_ip", account_id=account.account_id), "IP Info", bool(account.ip_address))}
      </div>
    </section>
    """


def _guilds_panel(
    account: OAuthAccount,
    guilds: list[dict[str, Any]],
    page: int,
    total_pages: int,
    member_details: dict[str, dict[str, Any]],
) -> str:
    sections = []
    for guild in guilds:
        guild_id = str(guild.get("id") or "unknown")
        detail = member_details.get(guild_id, {})
        joined = detail.get("joined_at")
        rows = [
            ("ID", _code(guild_id)),
            ("Owner", _h(_optional_bool(guild.get("owner")))),
            ("Permissions", _h(_guild_permissions(guild))),
        ]
        vanity = _guild_vanity_invite(guild)
        if vanity:
            rows.append(("Vanity Invite", f'<a href="{_h(vanity)}" target="_blank" rel="noreferrer">{_h(vanity)}</a>'))
        if joined:
            rows.append(("Joined", _h(_format_time_value(joined))))
        if guild.get("approximate_member_count") is not None:
            rows.append(("Approx. Members", _h(guild.get("approximate_member_count"))))
        if guild.get("approximate_presence_count") is not None:
            rows.append(("Approx. Online", _h(guild.get("approximate_presence_count"))))

        sections.append(
            f"""
            <article class="list-item media-item">
              <img class="server-icon" src="{_h(_guild_icon_url(guild))}" alt="">
              <div>
                <h2>{_h(guild.get("name") or "Unknown server")}</h2>
                {_compact_rows(rows)}
              </div>
            </article>
            """
        )

    if not sections:
        sections.append('<div class="empty-state"><p>No guilds were returned.</p></div>')

    return f"""
    <section class="workspace-panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Guilds</p>
          <h1>{_h(account.display_name)}</h1>
        </div>
        <div class="status-pill">Page {page + 1} of {total_pages}</div>
      </div>
      <div class="list-stack">{"".join(sections)}</div>
      {_pagination("account_guilds", account, page, total_pages)}
    </section>
    """


def _connections_panel(
    account: OAuthAccount,
    connections: list[dict[str, Any]],
    page: int,
    total_pages: int,
) -> str:
    items = []
    for connection in connections:
        name = (
            connection.get("name")
            or connection.get("username")
            or connection.get("id")
            or "Unknown"
        )
        rows = [
            ("ID", _code(connection.get("id") or "unknown")),
            ("Type", _h(connection.get("type") or "Unknown")),
            ("Verified", _h(_optional_bool(connection.get("verified")))),
            ("Visibility", _h(connection.get("visibility") or "Unknown")),
        ]
        items.append(
            f"""
            <article class="list-item">
              <h2>{_h(name)}</h2>
              {_compact_rows(rows)}
            </article>
            """
        )

    if not items:
        items.append('<div class="empty-state"><p>No connections were returned.</p></div>')

    return f"""
    <section class="workspace-panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Connections</p>
          <h1>{_h(account.display_name)}</h1>
        </div>
        <div class="status-pill">Page {page + 1} of {total_pages}</div>
      </div>
      <div class="list-stack">{"".join(items)}</div>
      {_pagination("account_connections", account, page, total_pages)}
    </section>
    """


def _relationships_panel(
    account: OAuthAccount,
    relationships: list[dict[str, Any]],
    page: int,
    total_pages: int,
) -> str:
    items = []
    for relationship in relationships:
        user = _relationship_user(relationship)
        name = _relationship_display_name(relationship)
        user_id = _relationship_user_id(relationship) or "unknown"
        rows = [
            ("User ID", _code(user_id)),
            ("Relationship", _h(_relationship_type_label(relationship))),
        ]
        username = user.get("username") or relationship.get("username")
        if username and username != name:
            rows.append(("Username", _h(username)))
        nickname = relationship.get("nickname") or relationship.get("nick")
        if nickname:
            rows.append(("Nickname", _h(nickname)))
        since = (
            relationship.get("since")
            or relationship.get("created_at")
            or relationship.get("createdAt")
            or relationship.get("updated_at")
            or relationship.get("updatedAt")
        )
        if since:
            rows.append(("Since", _h(_format_time_value(since))))

        items.append(
            f"""
            <article class="list-item media-item">
              <img class="avatar" src="{_h(_relationship_avatar_url(relationship))}" alt="">
              <div>
                <h2>{_h(name)}</h2>
                {_compact_rows(rows)}
              </div>
            </article>
            """
        )

    if not items:
        items.append('<div class="empty-state"><p>No relationships were returned.</p></div>')

    return f"""
    <section class="workspace-panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Relationships</p>
          <h1>{_h(account.display_name)}</h1>
        </div>
        <div class="status-pill">Page {page + 1} of {total_pages}</div>
      </div>
      <div class="list-stack">{"".join(items)}</div>
      {_pagination("account_relationships", account, page, total_pages)}
    </section>
    """


def _ip_panel(account: OAuthAccount, payload: dict[str, Any]) -> str:
    location = [
        ("Country", _h(_name_with_code(payload.get("country"), payload.get("country_code")))),
        ("Continent", _h(_name_with_code(payload.get("continent"), payload.get("continent_code")))),
    ]
    network = [
        ("IP Address", _code(payload.get("ip") or account.ip_address or "unknown")),
        ("ASN", _code(payload.get("asn") or "unknown")),
        ("Network Name", _h(payload.get("as_name") or "Unknown")),
        ("Network Domain", _h(payload.get("as_domain") or "Unknown")),
    ]
    return f"""
    <section class="workspace-panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">IP Info</p>
          <h1>{_h(account.ip_address or "Unknown IP")}</h1>
        </div>
      </div>
      <div class="section-block">
        <h2>Location</h2>
        {_field_grid(location)}
      </div>
      <div class="separator"></div>
      <div class="section-block">
        <h2>Network</h2>
        {_field_grid(network)}
      </div>
    </section>
    """


def _webhook_panel(account: OAuthAccount) -> str:
    disabled = not account.has_scope("webhook.incoming") or not account.has_webhook
    status = _webhook_status(account)
    return f"""
    <section class="workspace-panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Webhook</p>
          <h1>{_h(status)}</h1>
        </div>
      </div>
      <form class="form-panel" method="post" action="{url_for("send_webhook", account_id=account.account_id)}">
        {_csrf_input()}
        <label>
          <span>Username</span>
          <input name="username" maxlength="80" value="{_h(account.webhook_name or "")}" {"disabled" if disabled else ""}>
        </label>
        <label>
          <span>Message</span>
          <textarea name="content" rows="6" maxlength="1900" {"disabled" if disabled else ""}></textarea>
        </label>
        <button class="button primary" type="submit" {"disabled" if disabled else ""}>Send Webhook</button>
      </form>
    </section>
    """


def _error_panel(message: str) -> str:
    return f"""
    <section class="workspace-panel">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Error</p>
          <h1>Something went wrong</h1>
        </div>
      </div>
      <div class="notice error">{_h(message)}</div>
    </section>
    """


def _dashboard_shell(
    user: dict[str, Any],
    accounts: list[OAuthAccount],
    selected: OAuthAccount | None,
    content: str,
    notice: dict[str, str] | None,
) -> str:
    account_count = len(accounts)
    selected_id = selected.account_id if selected else None
    notice_html = ""
    if notice:
        notice_html = f'<div class="notice {_h(notice.get("level") or "success")}">{_h(notice.get("message") or "")}</div>'

    return f"""
    <main class="app-shell">
      <header class="topbar">
        <a class="brand" href="{url_for("home")}">
          <span class="brand-mark">A</span>
          <span>AuthSec</span>
        </a>
        <div class="signed-in">
          <img class="avatar small" src="{_h(_avatar_url(user))}" alt="">
          <span>{_h(_display_user(user))}</span>
          <a class="button subtle-button" href="{url_for("logout")}">Logout</a>
        </div>
      </header>
      <div class="dashboard-grid">
        <aside class="sidebar">
          <section class="stat-panel">
            <p class="eyebrow">Saved Accounts</p>
            <strong>{account_count}</strong>
            <span>of {MAX_ACCOUNTS_PER_OWNER}</span>
          </section>
          {_account_switcher(accounts, selected_id)}
          {_authorize_account_panel()}
        </aside>
        <section class="workspace">
          {notice_html}
          {content}
        </section>
      </div>
    </main>
    """


def _login_panel() -> str:
    return f"""
    <main class="login-shell">
      <section class="login-panel">
        <div class="brand-line">
          <span class="brand-mark">A</span>
          <span>AuthSec</span>
        </div>
        <h1>AuthSec Panel</h1>
        <p>Login with Discord to manage your saved accounts.</p>
        <a class="button primary login-button" href="{url_for("login")}">Login with Discord</a>
      </section>
    </main>
    """


def _account_switcher(accounts: list[OAuthAccount], selected_id: int | None) -> str:
    if not accounts:
        return """
        <section class="switcher">
          <p class="eyebrow">Accounts</p>
          <div class="empty-line">No accounts</div>
        </section>
        """

    if len(accounts) >= 5:
        options = "".join(
            f'<option value="{account.account_id}" {"selected" if account.account_id == selected_id else ""}>{_h(account.display_name)}</option>'
            for account in accounts
        )
        return f"""
        <section class="switcher">
          <p class="eyebrow">Accounts</p>
          <select class="account-select" onchange="window.location.href='/account/' + this.value">
            {options}
          </select>
        </section>
        """

    links = "".join(
        f"""
        <a class="account-tab {"active" if account.account_id == selected_id else ""}" href="{url_for("account_overview", account_id=account.account_id)}">
          <span>{_h(account.display_name)}</span>
          <small>{_h(account.discord_user_id)}</small>
        </a>
        """
        for account in accounts
    )
    return f"""
    <section class="switcher">
      <p class="eyebrow">Accounts</p>
      <div class="account-tabs">{links}</div>
    </section>
    """


def _authorize_account_panel() -> str:
    options = "".join(
        f"""
        <label class="scope-option">
          <input
            type="checkbox"
            name="scopes"
            value="{_h(scope)}"
            {"checked" if scope in DEFAULT_WEB_SETUP_SCOPES else ""}
          >
          <span>{_h(label)}</span>
        </label>
        """
        for scope, label in WEB_SCOPE_LABELS.items()
    )
    return f"""
    <form class="switcher setup-panel" method="post" action="{url_for("authorize_account")}" data-copy-link-form>
      {_csrf_input()}
      <p class="eyebrow">Authorize</p>
      <div class="scope-list">{options}</div>
      <button class="button primary" type="submit" data-copy-link-button>Create Link</button>
    </form>
    """


def _account_metrics(account: OAuthAccount) -> str:
    fields = [
        ("IP Address", _code(account.ip_address or "unknown")),
        ("MFA Enabled", _h(_optional_bool(account.mfa_enabled))),
        ("User Agent", _h(_truncate(account.user_agent or "unknown", 220))),
        ("Access", _h(_scope_list(account.scopes))),
        ("Token Expires", _h(_format_epoch(account.expires_at))),
        ("Last Updated", _h(_format_epoch(account.updated_at))),
    ]
    return _field_grid(fields)


def _account_action_bar(account: OAuthAccount) -> str:
    return f"""
    <nav class="action-row">
      {_link_button(url_for("account_details", account_id=account.account_id), "Details", True)}
      {_link_button(url_for("account_guilds", account_id=account.account_id), "Guilds", account.has_scope("guilds"))}
      {_link_button(url_for("account_connections", account_id=account.account_id), "Connections", account.has_scope("connections"))}
      {_link_button(url_for("account_relationships", account_id=account.account_id), "Relationships", account.has_scope("relationships.read"))}
      {_link_button(url_for("account_webhook", account_id=account.account_id), "Webhook", account.has_scope("webhook.incoming") and account.has_webhook)}
      {_link_button(url_for("account_ip", account_id=account.account_id), "IP Info", bool(account.ip_address))}
    </nav>
    """


def _account_admin_forms(account: OAuthAccount) -> str:
    return f"""
    <form class="form-panel compact" method="post" action="{url_for("refresh_account", account_id=account.account_id)}">
      {_csrf_input()}
      <h2>Token</h2>
      <button class="button primary" type="submit">Refresh Account</button>
    </form>
    <form class="form-panel compact" method="post" action="{url_for("disconnect_account", account_id=account.account_id)}" onsubmit="return confirm('Disconnect this saved account?')">
      {_csrf_input()}
      <h2>Disconnect</h2>
      <button class="button danger" type="submit">Disconnect Account</button>
    </form>
    """


def _join_guild_form(account: OAuthAccount) -> str:
    disabled = not account.has_scope("guilds.join")
    return f"""
    <form class="form-panel compact" method="post" action="{url_for("join_guild", account_id=account.account_id)}">
      {_csrf_input()}
      <h2>Join Guild</h2>
      <label>
        <span>Guild ID</span>
        <input name="guild_id" inputmode="numeric" pattern="[0-9]*" {"disabled" if disabled else ""}>
      </label>
      <p class="small-note">Discord sends a DM about the join.</p>
      <button class="button primary" type="submit" {"disabled" if disabled else ""}>Join Guild</button>
    </form>
    """


def _field_grid(fields: list[tuple[str, str]]) -> str:
    items = "".join(
        f"""
        <div class="field">
          <span>{_h(label)}</span>
          <strong>{value}</strong>
        </div>
        """
        for label, value in fields
    )
    return f'<div class="field-grid">{items}</div>'


def _compact_rows(rows: list[tuple[str, str]]) -> str:
    return "".join(
        f"""
        <p class="compact-row">
          <span>{_h(label)}</span>
          <strong>{value}</strong>
        </p>
        """
        for label, value in rows
    )


def _pagination(
    endpoint: str,
    account: OAuthAccount,
    page: int,
    total_pages: int,
) -> str:
    if total_pages <= 1:
        return ""

    prev_link = url_for(endpoint, account_id=account.account_id, page=max(0, page - 1))
    next_link = url_for(
        endpoint,
        account_id=account.account_id,
        page=min(total_pages - 1, page + 1),
    )
    return f"""
    <nav class="pagination">
      {_link_button(prev_link, "Previous", page > 0)}
      {_link_button(next_link, "Next", page < total_pages - 1)}
    </nav>
    """


def _link_button(href: str, label: str, enabled: bool) -> str:
    if not enabled:
        return f'<span class="button disabled" aria-disabled="true">{_h(label)}</span>'
    return f'<a class="button" href="{_h(href)}">{_h(label)}</a>'


def _csrf_token() -> str:
    token = session.get("csrf_token")
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _csrf_input() -> str:
    return f'<input type="hidden" name="csrf_token" value="{_h(_csrf_token())}">'


def _valid_csrf() -> bool:
    saved = session.get("csrf_token")
    posted = request.form.get("csrf_token")
    return bool(
        isinstance(saved, str)
        and isinstance(posted, str)
        and secrets.compare_digest(saved, posted)
    )


def _set_notice(message: str, level: str = "success") -> None:
    session["notice"] = {"message": message, "level": level}


def _pop_notice() -> dict[str, str] | None:
    notice = session.pop("notice", None)
    if isinstance(notice, dict):
        return {
            "message": str(notice.get("message") or ""),
            "level": str(notice.get("level") or "success"),
        }
    return None


def _page_number() -> int:
    try:
        return max(0, int(request.args.get("page", "0")))
    except ValueError:
        return 0


def _page_items(
    items: list[dict[str, Any]],
    page: int,
    page_size: int,
) -> tuple[list[dict[str, Any]], int, int]:
    total_pages = max(1, (len(items) + page_size - 1) // page_size)
    page = max(0, min(page, total_pages - 1))
    start = page * page_size
    return items[start : start + page_size], page, total_pages


def _page(title: str, message: str, status: int) -> Response:
    body = f"""
    <main class="login-shell">
      <section class="login-panel">
        <div class="brand-line">
          <span class="brand-mark">A</span>
          <span>AuthSec</span>
        </div>
        <h1>{_h(title)}</h1>
        <p>{_h(message)}</p>
      </section>
    </main>
    """
    return _page_response(title, body, status)


def _page_response(title: str, body: str, status: int = 200) -> Response:
    html_body = f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{_h(title)}</title>
        <style>
          :root {{
            color-scheme: light;
            font-family: Georgia, "Times New Roman", ui-serif, serif;
            background: #eee5d4;
            color: #2d251b;
          }}
          * {{
            box-sizing: border-box;
          }}
          body {{
            min-height: 100vh;
            margin: 0;
            background:
              linear-gradient(180deg, rgba(255, 251, 242, 0.94), rgba(229, 218, 198, 0.96)),
              repeating-linear-gradient(90deg, rgba(111, 73, 43, 0.05) 0 1px, transparent 1px 44px);
            color: #2d251b;
          }}
          @keyframes panelIn {{
            from {{
              opacity: 0;
              transform: translateY(10px);
            }}
            to {{
              opacity: 1;
              transform: translateY(0);
            }}
          }}
          @keyframes markPulse {{
            0%,
            100% {{
              box-shadow: 0 0 0 0 rgba(119, 31, 45, 0.24);
            }}
            50% {{
              box-shadow: 0 0 0 7px rgba(119, 31, 45, 0);
            }}
          }}
          @keyframes noticeIn {{
            from {{
              opacity: 0;
              transform: translateY(-6px);
            }}
            to {{
              opacity: 1;
              transform: translateY(0);
            }}
          }}
          a {{
            color: inherit;
          }}
          button,
          input,
          select,
          textarea {{
            font: inherit;
          }}
          .login-shell {{
            min-height: 100vh;
            display: grid;
            place-items: center;
            padding: 24px;
          }}
          .login-panel {{
            width: min(460px, 100%);
            border: 1px solid #b8a783;
            border-radius: 8px;
            background: #fffaf0;
            padding: 32px;
            box-shadow: 0 22px 60px rgba(71, 52, 30, 0.18);
            animation: panelIn 420ms ease-out both;
          }}
          .brand-line,
          .brand {{
            display: inline-flex;
            align-items: center;
            gap: 10px;
            text-decoration: none;
            color: #2d251b;
            font-weight: 750;
          }}
          .brand-mark {{
            width: 32px;
            height: 32px;
            display: grid;
            place-items: center;
            border-radius: 8px;
            background: #7a1f2f;
            color: #fffaf0;
            border: 1px solid #c39a4c;
            font-weight: 850;
            animation: markPulse 3s ease-in-out infinite;
          }}
          h1 {{
            margin: 12px 0 8px;
            font-size: clamp(28px, 5vw, 44px);
            line-height: 1.04;
            letter-spacing: 0;
            color: #2d251b;
          }}
          h2 {{
            margin: 0 0 12px;
            font-size: 16px;
            line-height: 1.25;
          }}
          p {{
            margin: 0;
            color: #6e604f;
            line-height: 1.55;
          }}
          .app-shell {{
            width: min(1360px, 100%);
            margin: 0 auto;
            padding: 18px;
          }}
          .topbar {{
            min-height: 64px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            border-bottom: 1px solid #c9b894;
          }}
          .signed-in {{
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 10px;
            color: #463b2e;
            min-width: 0;
          }}
          .signed-in span {{
            max-width: 30vw;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
          }}
          .avatar,
          .server-icon {{
            width: 44px;
            height: 44px;
            border-radius: 8px;
            object-fit: cover;
            background: #eee3d0;
            border: 1px solid #b8a783;
          }}
          .avatar.small {{
            width: 30px;
            height: 30px;
          }}
          .avatar.large {{
            width: 72px;
            height: 72px;
          }}
          .dashboard-grid {{
            display: grid;
            grid-template-columns: 310px minmax(0, 1fr);
            gap: 18px;
            padding-top: 18px;
          }}
          .sidebar,
          .workspace {{
            min-width: 0;
          }}
          .sidebar {{
            display: grid;
            gap: 14px;
            align-content: start;
          }}
          .stat-panel,
          .switcher,
          .workspace-panel,
          .form-panel,
          .list-item {{
            border: 1px solid #b8a783;
            border-radius: 8px;
            background: #fffaf0;
            box-shadow: 0 14px 32px rgba(71, 52, 30, 0.10);
            transition:
              border-color 180ms ease,
              box-shadow 180ms ease,
              transform 180ms ease,
              background-color 180ms ease;
          }}
          .stat-panel,
          .switcher {{
            padding: 18px;
          }}
          .stat-panel strong {{
            display: inline-block;
            margin-top: 8px;
            font-size: 42px;
            line-height: 1;
          }}
          .stat-panel span {{
            color: #776954;
            margin-left: 6px;
          }}
          .eyebrow {{
            margin: 0;
            color: #7a1f2f;
            font-size: 12px;
            font-weight: 760;
            text-transform: uppercase;
            letter-spacing: 0;
          }}
          .account-tabs {{
            display: grid;
            gap: 8px;
            margin-top: 12px;
          }}
          .account-tab {{
            display: grid;
            gap: 3px;
            padding: 10px;
            border: 1px solid #c5b38e;
            border-radius: 8px;
            text-decoration: none;
            background: #fbf4e8;
            transition:
              border-color 180ms ease,
              background-color 180ms ease,
              transform 180ms ease;
          }}
          .account-tab:hover {{
            border-color: #8b6f3d;
            transform: translateY(-1px);
          }}
          .account-tab.active {{
            border-color: #7a1f2f;
            background: #f4e8d7;
          }}
          .account-tab span,
          .account-tab small {{
            min-width: 0;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
          }}
          .account-tab small,
          .empty-line,
          .small-note {{
            color: #776954;
          }}
          .account-select {{
            width: 100%;
            margin-top: 12px;
            border: 1px solid #b8a783;
            border-radius: 8px;
            background: #fffaf0;
            color: #2d251b;
            padding: 10px 12px;
          }}
          .setup-panel {{
            display: grid;
            gap: 12px;
          }}
          .scope-list {{
            display: grid;
            gap: 8px;
          }}
          .scope-option {{
            display: grid;
            grid-template-columns: 18px minmax(0, 1fr);
            align-items: center;
            gap: 8px;
            color: #463b2e;
            font-size: 13px;
            font-weight: 650;
          }}
          .scope-option input {{
            width: 16px;
            height: 16px;
            padding: 0;
            accent-color: #7a1f2f;
          }}
          .workspace {{
            display: grid;
            gap: 12px;
          }}
          .workspace-panel {{
            padding: 22px;
            animation: panelIn 360ms ease-out both;
          }}
          .panel-head {{
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 18px;
          }}
          .panel-head h1 {{
            margin: 4px 0;
            font-size: clamp(26px, 3vw, 38px);
          }}
          .subtle {{
            color: #776954;
          }}
          .status-pill {{
            flex: 0 0 auto;
            border: 1px solid #c5b38e;
            border-radius: 999px;
            color: #3c2e1f;
            background: #f5ead9;
            padding: 8px 12px;
            font-size: 13px;
            font-weight: 720;
          }}
          .field-grid {{
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
          }}
          .field {{
            min-width: 0;
            border: 1px solid #c9b894;
            border-radius: 8px;
            background: #fbf4e8;
            padding: 12px;
            transition:
              border-color 180ms ease,
              transform 180ms ease,
              background-color 180ms ease;
          }}
          .field:hover {{
            border-color: #8b6f3d;
            background: #fff7eb;
            transform: translateY(-1px);
          }}
          .field span,
          .compact-row span {{
            display: block;
            color: #776954;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0;
          }}
          .field strong,
          .compact-row strong {{
            display: block;
            min-width: 0;
            margin-top: 5px;
            color: #2d251b;
            font-size: 14px;
            line-height: 1.45;
            overflow-wrap: anywhere;
          }}
          code {{
            color: #263853;
            background: #efe3ce;
            border: 1px solid #cbb890;
            border-radius: 6px;
            padding: 2px 5px;
          }}
          .action-row,
          .pagination {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 16px;
          }}
          .button {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-height: 38px;
            border: 1px solid #b8a783;
            border-radius: 8px;
            background: #f7efe2;
            color: #2d251b;
            padding: 8px 12px;
            text-decoration: none;
            font-weight: 720;
            cursor: pointer;
            transition:
              border-color 160ms ease,
              background-color 160ms ease,
              transform 160ms ease,
              box-shadow 160ms ease;
          }}
          .button:hover:not(.disabled):not(:disabled) {{
            border-color: #8b6f3d;
            transform: translateY(-1px);
            box-shadow: 0 10px 24px rgba(71, 52, 30, 0.16);
          }}
          .button:active:not(.disabled):not(:disabled) {{
            transform: translateY(0);
          }}
          .button.primary {{
            background: #24344f;
            border-color: #24344f;
            color: #fffaf0;
          }}
          .button.danger {{
            background: #8a2435;
            border-color: #8a2435;
            color: #fffaf0;
          }}
          .button.disabled,
          .button:disabled {{
            opacity: 0.46;
            cursor: not-allowed;
          }}
          .subtle-button {{
            min-height: 32px;
            padding: 6px 10px;
            background: #fbf4e8;
          }}
          .login-button {{
            width: 100%;
            margin-top: 22px;
          }}
          .split-grid {{
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 10px;
            margin-top: 16px;
          }}
          .form-panel {{
            display: grid;
            gap: 10px;
            padding: 16px;
          }}
          label {{
            display: grid;
            gap: 6px;
            color: #463b2e;
            font-size: 13px;
            font-weight: 720;
          }}
          input,
          textarea {{
            width: 100%;
            border: 1px solid #b8a783;
            border-radius: 8px;
            background: #fffaf0;
            color: #2d251b;
            padding: 10px 11px;
            resize: vertical;
          }}
          .list-stack {{
            display: grid;
            gap: 10px;
          }}
          .list-item {{
            padding: 14px;
            animation: panelIn 300ms ease-out both;
          }}
          .list-item:hover {{
            border-color: #8b6f3d;
            transform: translateY(-1px);
          }}
          .list-item h2 {{
            margin: 0 0 8px;
          }}
          .media-item {{
            display: grid;
            grid-template-columns: 52px minmax(0, 1fr);
            gap: 12px;
          }}
          .compact-row {{
            display: grid;
            grid-template-columns: 150px minmax(0, 1fr);
            gap: 8px;
            margin-top: 8px;
          }}
          .notice {{
            border: 1px solid #668a5a;
            border-radius: 8px;
            background: #edf5e8;
            color: #314c2c;
            padding: 12px 14px;
            animation: noticeIn 260ms ease-out both;
          }}
          .notice.error {{
            border-color: #a45a64;
            background: #f8e6e4;
            color: #6f1f2f;
          }}
          .empty-state {{
            border: 1px dashed #b8a783;
            border-radius: 8px;
            padding: 18px;
            background: #fbf4e8;
          }}
          .section-block {{
            display: grid;
            gap: 10px;
          }}
          .separator {{
            height: 1px;
            background: #c9b894;
            margin: 18px 0;
          }}
          @media (max-width: 900px) {{
            .dashboard-grid,
            .split-grid {{
              grid-template-columns: 1fr;
            }}
            .field-grid {{
              grid-template-columns: 1fr;
            }}
            .topbar,
            .panel-head {{
              align-items: flex-start;
              flex-direction: column;
            }}
            .signed-in {{
              width: 100%;
              justify-content: flex-start;
            }}
            .signed-in span {{
              max-width: 58vw;
            }}
            .compact-row {{
              grid-template-columns: 1fr;
            }}
          }}
          @media (prefers-reduced-motion: reduce) {{
            *,
            *::before,
            *::after {{
              animation-duration: 1ms !important;
              animation-iteration-count: 1 !important;
              scroll-behavior: auto !important;
              transition-duration: 1ms !important;
            }}
          }}
        </style>
      </head>
      <body>
        {body}
        <script>
          (() => {{
            const copiedText = "Link copied!";
            const errorText = "Copy failed";

            const fallbackCopy = (text) => {{
              const textarea = document.createElement("textarea");
              textarea.value = text;
              textarea.setAttribute("readonly", "");
              textarea.style.position = "fixed";
              textarea.style.top = "-999px";
              textarea.style.left = "-999px";
              document.body.appendChild(textarea);
              textarea.select();
              const copied = document.execCommand("copy");
              textarea.remove();
              if (!copied) {{
                throw new Error("copy failed");
              }}
            }};

            const copyText = async (text) => {{
              if (navigator.clipboard && window.isSecureContext) {{
                await navigator.clipboard.writeText(text);
                return;
              }}
              fallbackCopy(text);
            }};

            const resetButton = (button, originalText) => {{
              window.clearTimeout(Number(button.dataset.copyResetTimer || 0));
              button.dataset.copyResetTimer = String(window.setTimeout(() => {{
                button.textContent = originalText;
                button.disabled = false;
              }}, 2000));
            }};

            document.querySelectorAll("[data-copy-link-form]").forEach((form) => {{
              form.addEventListener("submit", async (event) => {{
                event.preventDefault();
                const button = form.querySelector("[data-copy-link-button]");
                if (!button) {{
                  return;
                }}

                const originalText = button.dataset.originalText || button.textContent;
                button.dataset.originalText = originalText;
                button.disabled = true;

                try {{
                  const response = await fetch(form.action, {{
                    method: "POST",
                    body: new FormData(form),
                    credentials: "same-origin",
                    headers: {{
                      "Accept": "application/json",
                      "X-AuthSec-Copy-Link": "1",
                    }},
                  }});
                  if (!response.ok) {{
                    throw new Error("request failed");
                  }}

                  const payload = await response.json();
                  if (!payload.url) {{
                    throw new Error("missing url");
                  }}

                  await copyText(payload.url);
                  button.textContent = copiedText;
                }} catch (error) {{
                  button.textContent = errorText;
                }} finally {{
                  resetButton(button, originalText);
                }}
              }});
            }});
          }})();
        </script>
      </body>
    </html>
    """
    return Response(html_body, status=status, mimetype="text/html")


def _close_tab_page() -> Response:
    body = """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title></title>
        <script>
          window.open("", "_self");
          window.close();
          setTimeout(() => {
            document.body.textContent = "";
          }, 50);
        </script>
      </head>
      <body></body>
    </html>
    """
    return Response(body, status=200, mimetype="text/html")


def _guild_icon_url(guild: dict[str, Any]) -> str:
    guild_id = guild.get("id")
    icon_hash = guild.get("icon")
    if guild_id and icon_hash:
        extension = "gif" if str(icon_hash).startswith("a_") else "webp"
        return f"https://cdn.discordapp.com/icons/{guild_id}/{icon_hash}.{extension}?size=128"

    return "https://cdn.discordapp.com/embed/avatars/0.png"


def _guild_permissions(guild: dict[str, Any]) -> str:
    raw_permissions = guild.get("permissions")
    if raw_permissions is None:
        return "Unknown"

    try:
        permissions = discord.Permissions(int(raw_permissions))
    except (TypeError, ValueError):
        return "Unknown"

    if permissions.administrator:
        return "Administrator"

    labels = [_permission_label(name) for name, enabled in permissions if enabled]
    if labels:
        return ", ".join(labels)
    return "None"


def _permission_label(name: str) -> str:
    overrides = {
        "administrator": "Administrator",
        "manage_guild": "Manage Server",
        "manage_emojis": "Manage Expressions",
        "manage_emojis_and_stickers": "Manage Expressions",
        "use_slash_commands": "Use Application Commands",
    }
    if name in overrides:
        return overrides[name]
    return name.replace("_", " ").title()


def _guild_vanity_invite(guild: dict[str, Any]) -> str | None:
    value = (
        guild.get("vanity_url_code")
        or guild.get("vanity_invite")
        or guild.get("vanity_url")
    )
    if not value:
        return None

    text = str(value)
    if text.startswith("http://") or text.startswith("https://"):
        return text
    return f"https://discord.gg/{text}"


def _relationship_user(relationship: dict[str, Any]) -> dict[str, Any]:
    for key in ("user", "discord_user", "discordUser", "recipient"):
        value = relationship.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _relationship_display_name(relationship: dict[str, Any]) -> str:
    user = _relationship_user(relationship)
    return str(
        user.get("global_name")
        or user.get("display_name")
        or user.get("username")
        or relationship.get("global_name")
        or relationship.get("display_name")
        or relationship.get("username")
        or _relationship_user_id(relationship)
        or "Unknown user"
    )


def _relationship_user_id(relationship: dict[str, Any]) -> str | None:
    user = _relationship_user(relationship)
    value = (
        user.get("id")
        or relationship.get("user_id")
        or relationship.get("userId")
        or relationship.get("id")
    )
    if value is None:
        return None
    return str(value)


def _relationship_avatar_url(relationship: dict[str, Any]) -> str:
    user = _relationship_user(relationship)
    user_id = _relationship_user_id(relationship)
    avatar_hash = user.get("avatar") or relationship.get("avatar")
    if user_id and avatar_hash:
        extension = "gif" if str(avatar_hash).startswith("a_") else "webp"
        return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.{extension}?size=128"

    return "https://cdn.discordapp.com/embed/avatars/0.png"


def _relationship_type_label(relationship: dict[str, Any]) -> str:
    value = None
    for key in (
        "type",
        "relationship_type",
        "relationshipType",
        "discord_relationship_type",
        "discordRelationshipType",
        "discord_type",
    ):
        if key in relationship and relationship[key] is not None:
            value = relationship[key]
            break

    if value is None:
        return "Unknown"

    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            value = int(text)
        else:
            return text.replace("_", " ").replace("-", " ").title()

    labels = {
        0: "None",
        1: "Friend",
        2: "Blocked",
        3: "Incoming Request",
        4: "Outgoing Request",
        5: "Implicit",
    }
    return labels.get(value, str(value))


def _avatar_url(user: dict[str, Any]) -> str:
    user_id = user.get("id")
    avatar_hash = user.get("avatar")
    if user_id and avatar_hash:
        extension = "gif" if str(avatar_hash).startswith("a_") else "webp"
        return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.{extension}?size=128"
    return "https://cdn.discordapp.com/embed/avatars/0.png"


def _display_user(user: dict[str, Any]) -> str:
    return str(user.get("global_name") or user.get("username") or user.get("id"))


def _mfa_text(value: bool | None) -> str:
    return f"MFA: {_optional_bool(value)}"


def _optional_bool(value: Any) -> str:
    if value is None:
        return "Unknown"
    return "Yes" if bool(value) else "No"


def _name_with_code(name_value: Any, code_value: Any) -> str:
    name = str(name_value).strip() if name_value else ""
    code = str(code_value).strip() if code_value else ""
    if name and code:
        return f"{name} ({code})"
    return name or code or "Unknown"


def _webhook_status(account: OAuthAccount) -> str:
    if not account.has_webhook:
        return "Not stored"

    parts = ["Stored"]
    if account.webhook_name:
        parts.append(account.webhook_name)
    if account.webhook_channel_id:
        parts.append(f"channel {account.webhook_channel_id}")
    if account.webhook_guild_id:
        parts.append(f"guild {account.webhook_guild_id}")
    return " - ".join(parts)


def _scope_list(scopes: list[str]) -> str:
    labels = {"identify": "Identify", **WEB_SCOPE_LABELS}
    return ", ".join(labels.get(scope, scope) for scope in scopes) or "None"


def _format_epoch(value: int) -> str:
    try:
        parsed = datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return "Unknown"
    return parsed.strftime("%b %d, %Y at %H:%M UTC")


def _format_time_value(value: Any) -> str:
    timestamp = _value_timestamp(value)
    if timestamp is None:
        return str(value)
    return _format_epoch(timestamp)


def _value_timestamp(value: Any) -> int | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        return int(value)
    elif isinstance(value, str):
        parsed = _parse_datetime_string(value)
        if parsed is None:
            return None
    else:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def _parse_datetime_string(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _truncate(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value
    return f"{value[: max_length - 3]}..."


def _code(value: Any) -> str:
    return f"<code>{_h(value)}</code>"


def _h(value: Any) -> str:
    return html.escape(str(value), quote=True)
