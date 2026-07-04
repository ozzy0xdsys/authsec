from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from threading import RLock

from .models import OAuthAccount, OAuthState, scopes_from_json, scopes_to_json


class AuthDatabase:
    def __init__(self, path: Path):
        self.path = path
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = RLock()
        self._connection = sqlite3.connect(
            str(path),
            check_same_thread=False,
            isolation_level=None,
            timeout=10,
        )
        self._connection.row_factory = sqlite3.Row
        self._configure()
        self.migrate()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _configure(self) -> None:
        with self._lock:
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 10000")
            if str(self.path) != ":memory:":
                self._connection.execute("PRAGMA journal_mode = WAL")

    def migrate(self) -> None:
        with self._lock:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS oauth_accounts (
                    owner_id INTEGER PRIMARY KEY,
                    discord_user_id TEXT NOT NULL,
                    username TEXT,
                    global_name TEXT,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    token_type TEXT NOT NULL DEFAULT 'Bearer',
                    expires_at INTEGER NOT NULL,
                    scopes TEXT NOT NULL,
                    ip_address TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS oauth_states (
                    state TEXT PRIMARY KEY,
                    owner_id INTEGER NOT NULL,
                    scopes TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    used_at INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_oauth_states_owner
                    ON oauth_states(owner_id);

                CREATE TABLE IF NOT EXISTS event_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER,
                    event_type TEXT NOT NULL,
                    details TEXT,
                    created_at INTEGER NOT NULL
                );
                """
            )

    def save_state(
        self,
        state: str,
        owner_id: int,
        scopes: list[str],
        ttl_seconds: int,
    ) -> OAuthState:
        now = _now()
        item = OAuthState(
            state=state,
            owner_id=int(owner_id),
            scopes=scopes,
            created_at=now,
            expires_at=now + int(ttl_seconds),
        )

        with self._lock:
            self._connection.execute(
                """
                INSERT INTO oauth_states
                    (state, owner_id, scopes, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    item.state,
                    item.owner_id,
                    scopes_to_json(item.scopes),
                    item.created_at,
                    item.expires_at,
                ),
            )

        return item

    def consume_state(self, state: str) -> OAuthState | None:
        now = _now()
        with self._lock:
            row = self._connection.execute(
                """
                SELECT state, owner_id, scopes, created_at, expires_at
                FROM oauth_states
                WHERE state = ?
                  AND used_at IS NULL
                  AND expires_at >= ?
                """,
                (state, now),
            ).fetchone()

            if row is None:
                return None

            self._connection.execute(
                "UPDATE oauth_states SET used_at = ? WHERE state = ?",
                (now, state),
            )

        return OAuthState(
            state=row["state"],
            owner_id=int(row["owner_id"]),
            scopes=scopes_from_json(row["scopes"]),
            created_at=int(row["created_at"]),
            expires_at=int(row["expires_at"]),
        )

    def cleanup_states(self) -> None:
        with self._lock:
            self._connection.execute(
                "DELETE FROM oauth_states WHERE expires_at < ? OR used_at IS NOT NULL",
                (_now(),),
            )

    def save_account(self, account: OAuthAccount) -> OAuthAccount:
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO oauth_accounts (
                    owner_id,
                    discord_user_id,
                    username,
                    global_name,
                    access_token,
                    refresh_token,
                    token_type,
                    expires_at,
                    scopes,
                    ip_address,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(owner_id) DO UPDATE SET
                    discord_user_id = excluded.discord_user_id,
                    username = excluded.username,
                    global_name = excluded.global_name,
                    access_token = excluded.access_token,
                    refresh_token = excluded.refresh_token,
                    token_type = excluded.token_type,
                    expires_at = excluded.expires_at,
                    scopes = excluded.scopes,
                    ip_address = excluded.ip_address,
                    updated_at = excluded.updated_at
                """,
                (
                    account.owner_id,
                    account.discord_user_id,
                    account.username,
                    account.global_name,
                    account.access_token,
                    account.refresh_token,
                    account.token_type,
                    account.expires_at,
                    scopes_to_json(account.scopes),
                    account.ip_address,
                    account.created_at,
                    account.updated_at,
                ),
            )

        saved = self.get_account(account.owner_id)
        if saved is None:
            raise RuntimeError("Failed to save OAuth account.")
        return saved

    def get_account(self, owner_id: int) -> OAuthAccount | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT *
                FROM oauth_accounts
                WHERE owner_id = ?
                """,
                (int(owner_id),),
            ).fetchone()

        if row is None:
            return None
        return _account_from_row(row)

    def delete_account(self, owner_id: int) -> None:
        with self._lock:
            self._connection.execute(
                "DELETE FROM oauth_accounts WHERE owner_id = ?",
                (int(owner_id),),
            )

    def log_event(
        self,
        event_type: str,
        owner_id: int | None = None,
        details: str | None = None,
    ) -> None:
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO event_log (owner_id, event_type, details, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (owner_id, event_type, details, _now()),
            )


def _account_from_row(row: sqlite3.Row) -> OAuthAccount:
    return OAuthAccount(
        owner_id=int(row["owner_id"]),
        discord_user_id=str(row["discord_user_id"]),
        username=row["username"],
        global_name=row["global_name"],
        access_token=row["access_token"],
        refresh_token=row["refresh_token"],
        token_type=row["token_type"],
        expires_at=int(row["expires_at"]),
        scopes=scopes_from_json(row["scopes"]),
        ip_address=row["ip_address"],
        created_at=int(row["created_at"]),
        updated_at=int(row["updated_at"]),
    )


def _now() -> int:
    return int(time.time())
