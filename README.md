# AuthSec

AuthSec is a Discord bot plus a Flask website for Discord OAuth.

## What It Does

- `/setup` lets a user choose OAuth scopes and creates a Discord authorization link.
  - Authorization links can be one-use, limited-use, or unlimited-use.
  - Links default to forever/unlimited uses, or can be limited by time and uses.
  - The generated link response includes a raw copyable URL and a `Post Here` button for posting a public authorization button.
- `/create` posts a reusable button message for an OAuth link.
- `/panel` shows the linked account and provides working actions:
  - refresh tokens
  - view current user details and look up saved callback IP geolocation
  - show the callback IP address stored when OAuth completes
  - show whether MFA is enabled when Discord includes `mfa_enabled` in the OAuth user payload
  - list guilds two per page with server icons, ownership, IDs, decoded permissions, vanity invite data, join dates, counts, and pagination
  - list connections when the `connections` scope is granted
  - list relationships two per page with user avatars, IDs, decoded relationship types, and pagination
  - send messages through the OAuth webhook returned by `webhook.incoming`
  - add the linked account to the current server when `guilds.join` is granted and the bot has administrator in that server
  - warn before a server join that Discord will send the linked account a DM
  - disconnect and revoke the token
- `/encryption` lets a user enable AES encryption for saved access tokens, refresh tokens, IP addresses, user agents, and webhook tokens.
  - The password is verified with a SHA-256 hash and the raw password is only kept in memory while unlocked.
  - Encrypted users enter the password every time they run `/panel`.
  - The panel button timeout can be set from 3 to 30 minutes, and the panel shows when its buttons will disable.
- `/faq` explains the bot behavior.
- `/ping` confirms the bot is alive.

The Discord command UI uses Discord components v2 (`LayoutView`, containers, text displays, and action rows).
The owner-only `?` commands require the Discord Message Content intent to be enabled for the bot.

## Files

- `main.py` starts everything.
- `authsec/app.py` wires the app together.
- `authsec/settings.py` loads config.
- `authsec/database.py` owns SQLite setup and queries.
- `authsec/oauth.py` talks to Discord OAuth/API endpoints.
- `authsec/bot.py` registers Discord commands.
- `authsec/ui.py` contains embeds, modals, selects, and buttons.
- `authsec/web.py` contains the Flask OAuth callback endpoint.

## Config

The app still supports the old flat `config.json` shape:

```json
{
  "token": "BOT_TOKEN",
  "id": "CLIENT_ID",
  "secret": "CLIENT_SECRET"
}
```

For future edits, use the clearer nested shape in `config.example.json`.

You can also use environment variables on a VPS:

```bash
export DISCORD_TOKEN="BOT_TOKEN"
export DISCORD_CLIENT_ID="CLIENT_ID"
export DISCORD_CLIENT_SECRET="CLIENT_SECRET"
export AUTHSEC_WEB_PORT="80"
export AUTHSEC_REDIRECT_URI="https://authsec.xyz/callback"
export AUTHSEC_CLEAR_WEB_PORT="true"
export AUTHSEC_IPSTACK_BASE_URL="https://dashboard.ipstack.com/iplookup/ipstack_api.php"
export AUTHSEC_IPSTACK_ORIGIN="https://ipstack.com"
```

## Database

The old `database.json` file is gone. On startup, the app creates `authsec.sqlite3`
and applies the schema automatically.

## Run

```powershell
.\.venv\Scripts\python.exe main.py
```

Make sure the redirect URI in Discord's developer portal matches the `web.redirect_uri`
value in config.

## Quick Deploy

Push from your computer:

```bash
git status
git add .
git commit -m "Update OAuth bot with SQLite and components v2"
git push origin main
```

Update on the VPS:

```bash
cd /root/authsec
git pull origin main
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python main.py
```

If you run it with systemd, restart the service instead of running `python main.py`
directly:

```bash
sudo systemctl restart authsec
sudo journalctl -u authsec -f
```

By default, startup stops any process already listening on the configured web
port before binding it. Set `AUTHSEC_CLEAR_WEB_PORT=false` to disable that.
