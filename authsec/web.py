from __future__ import annotations

import html

from flask import Flask, Response, jsonify, redirect, request

from .bot import BotRuntime
from .oauth import DiscordApiError, DiscordOAuthClient


def create_web_app(oauth_client: DiscordOAuthClient, bot_runtime: BotRuntime) -> Flask:
    app = Flask(__name__)
    settings = oauth_client.settings

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
        return _page(
            "AuthSec is running",
            "The Discord bot and OAuth callback website are online.",
            200,
        )

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

        try:
            account = oauth_client.complete_authorization(
                code=code,
                state=state,
                ip_address=_client_ip(),
            )
        except DiscordApiError as exc:
            return _page("Authorization failed", str(exc), exc.status_code)

        dm_scheduled = bot_runtime.notify_linked_account(account)
        suffix = (
            "A confirmation DM is on the way."
            if dm_scheduled
            else "Return to Discord and run /panel."
        )
        return _page(
            "Authorization complete",
            f"{account.display_name} is linked. {suffix}",
            200,
        )

    return app


def _client_ip() -> str | None:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr


def _is_local_request() -> bool:
    host = request.host.split(":", 1)[0].lower()
    return host in {"127.0.0.1", "localhost", "::1"}


def _page(title: str, message: str, status: int) -> Response:
    escaped_title = html.escape(title)
    escaped_message = html.escape(message)
    body = f"""
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{escaped_title}</title>
        <style>
          :root {{
            color-scheme: dark;
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #111318;
            color: #f5f7fb;
          }}
          body {{
            min-height: 100vh;
            margin: 0;
            display: grid;
            place-items: center;
            padding: 24px;
          }}
          main {{
            width: min(560px, 100%);
            border: 1px solid #2b303b;
            border-radius: 8px;
            padding: 28px;
            background: #191c23;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.25);
          }}
          h1 {{
            margin: 0 0 12px;
            font-size: 28px;
            line-height: 1.15;
          }}
          p {{
            margin: 0;
            color: #c8ceda;
            line-height: 1.55;
          }}
        </style>
      </head>
      <body>
        <main>
          <h1>{escaped_title}</h1>
          <p>{escaped_message}</p>
        </main>
      </body>
    </html>
    """
    return Response(body, status=status, mimetype="text/html")
