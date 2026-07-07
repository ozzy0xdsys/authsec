from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from threading import RLock

from .models import (
    DEFAULT_OAUTH_LINK_USE_LIMIT,
    DEFAULT_PANEL_TIMEOUT_SECONDS,
    MAX_ACCOUNTS_PER_OWNER,
    OAuthAccount,
    OAuthState,
    OwnerSecuritySettings,
    scopes_from_json,
    scopes_to_json,
)


class AccountLimitError(RuntimeError):
    pass


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
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL,
                    discord_user_id TEXT NOT NULL,
                    username TEXT,
                    global_name TEXT,
                    mfa_enabled INTEGER,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    token_type TEXT NOT NULL DEFAULT 'Bearer',
                    expires_at INTEGER NOT NULL,
                    scopes TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    webhook_id TEXT,
                    webhook_token TEXT,
                    webhook_channel_id TEXT,
                    webhook_guild_id TEXT,
                    webhook_name TEXT,
                    UNIQUE(owner_id, discord_user_id)
                );

                CREATE TABLE IF NOT EXISTS oauth_states (
                    state TEXT PRIMARY KEY,
                    owner_id INTEGER NOT NULL,
                    scopes TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    used_at INTEGER,
                    use_limit INTEGER DEFAULT 1,
                    used_count INTEGER NOT NULL DEFAULT 0
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

                CREATE TABLE IF NOT EXISTS owner_security_settings (
                    owner_id INTEGER PRIMARY KEY,
                    password_hash TEXT,
                    encryption_enabled INTEGER NOT NULL DEFAULT 0,
                    panel_timeout_seconds INTEGER NOT NULL DEFAULT 300,
                    updated_at INTEGER NOT NULL
                );
                """
            )
            self._ensure_column("oauth_accounts", "mfa_enabled", "INTEGER")
            self._ensure_column("oauth_accounts", "user_agent", "TEXT")
            self._ensure_column("oauth_accounts", "webhook_id", "TEXT")
            self._ensure_column("oauth_accounts", "webhook_token", "TEXT")
            self._ensure_column("oauth_accounts", "webhook_channel_id", "TEXT")
            self._ensure_column("oauth_accounts", "webhook_guild_id", "TEXT")
            self._ensure_column("oauth_accounts", "webhook_name", "TEXT")
            self._ensure_column(
                "oauth_states",
                "use_limit",
                "INTEGER DEFAULT 1",
            )
            self._ensure_column(
                "oauth_states",
                "used_count",
                "INTEGER NOT NULL DEFAULT 0",
            )
            self._connection.execute(
                """
                UPDATE oauth_states
                SET used_count = 1
                WHERE used_at IS NOT NULL
                  AND used_count = 0
                """
            )
            self._ensure_column("owner_security_settings", "password_hash", "TEXT")
            self._ensure_column(
                "owner_security_settings",
                "encryption_enabled",
                "INTEGER NOT NULL DEFAULT 0",
            )
            self._ensure_column(
                "owner_security_settings",
                "panel_timeout_seconds",
                "INTEGER NOT NULL DEFAULT 300",
            )
            self._ensure_column(
                "owner_security_settings",
                "updated_at",
                "INTEGER NOT NULL DEFAULT 0",
            )
            self._migrate_oauth_accounts_primary_key()
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_oauth_accounts_owner
                    ON oauth_accounts(owner_id)
                """
            )
            self._connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_accounts_owner_discord_user
                    ON oauth_accounts(owner_id, discord_user_id)
                """
            )

    def save_state(
        self,
        state: str,
        owner_id: int,
        scopes: list[str],
        ttl_seconds: int,
        use_limit: int | None = DEFAULT_OAUTH_LINK_USE_LIMIT,
    ) -> OAuthState:
        now = _now()
        item = OAuthState(
            state=state,
            owner_id=int(owner_id),
            scopes=scopes,
            created_at=now,
            expires_at=now + int(ttl_seconds),
            use_limit=use_limit,
            used_count=0,
        )

        with self._lock:
            self._connection.execute(
                """
                INSERT INTO oauth_states
                    (state, owner_id, scopes, created_at, expires_at, use_limit, used_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.state,
                    item.owner_id,
                    scopes_to_json(item.scopes),
                    item.created_at,
                    item.expires_at,
                    item.use_limit,
                    item.used_count,
                ),
            )

        return item

    def consume_state(self, state: str) -> OAuthState | None:
        now = _now()
        with self._lock:
            row = self._connection.execute(
                """
                SELECT state, owner_id, scopes, created_at, expires_at,
                       use_limit, used_count
                FROM oauth_states
                WHERE state = ?
                  AND expires_at >= ?
                  AND (
                    use_limit IS NULL
                    OR used_count < use_limit
                  )
                """,
                (state, now),
            ).fetchone()

            if row is None:
                return None

            self._connection.execute(
                """
                UPDATE oauth_states
                SET used_at = ?,
                    used_count = used_count + 1
                WHERE state = ?
                """,
                (now, state),
            )

        return _state_from_row(row, used_count_offset=1)

    def get_valid_state(self, state: str) -> OAuthState | None:
        now = _now()
        with self._lock:
            row = self._connection.execute(
                """
                SELECT state, owner_id, scopes, created_at, expires_at,
                       use_limit, used_count
                FROM oauth_states
                WHERE state = ?
                  AND expires_at >= ?
                  AND (
                    use_limit IS NULL
                    OR used_count < use_limit
                  )
                """,
                (state, now),
            ).fetchone()

        if row is None:
            return None
        return _state_from_row(row)

    def cleanup_states(self) -> None:
        with self._lock:
            self._connection.execute(
                """
                DELETE FROM oauth_states
                WHERE expires_at < ?
                   OR (
                    use_limit IS NOT NULL
                    AND used_count >= use_limit
                  )
                """,
                (_now(),),
            )

    def get_security_settings(self, owner_id: int) -> OwnerSecuritySettings:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT owner_id, password_hash, encryption_enabled,
                       panel_timeout_seconds, updated_at
                FROM owner_security_settings
                WHERE owner_id = ?
                """,
                (int(owner_id),),
            ).fetchone()

        if row is None:
            return OwnerSecuritySettings(
                owner_id=int(owner_id),
                password_hash=None,
                encryption_enabled=False,
                panel_timeout_seconds=DEFAULT_PANEL_TIMEOUT_SECONDS,
                updated_at=0,
            )

        return _security_settings_from_row(row)

    def save_security_settings(
        self,
        settings: OwnerSecuritySettings,
    ) -> OwnerSecuritySettings:
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO owner_security_settings (
                    owner_id,
                    password_hash,
                    encryption_enabled,
                    panel_timeout_seconds,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(owner_id) DO UPDATE SET
                    password_hash = excluded.password_hash,
                    encryption_enabled = excluded.encryption_enabled,
                    panel_timeout_seconds = excluded.panel_timeout_seconds,
                    updated_at = excluded.updated_at
                """,
                (
                    int(settings.owner_id),
                    settings.password_hash,
                    _bool_to_int(settings.encryption_enabled),
                    int(settings.panel_timeout_seconds),
                    int(settings.updated_at),
                ),
            )

        return self.get_security_settings(settings.owner_id)

    def save_account(self, account: OAuthAccount) -> OAuthAccount:
        with self._lock:
            existing = self._find_existing_account_row(account)
            if existing is None:
                account_count = self._account_count(account.owner_id)
                if account_count >= MAX_ACCOUNTS_PER_OWNER:
                    raise AccountLimitError(
                        f"You can store up to {MAX_ACCOUNTS_PER_OWNER} linked accounts. "
                        "Disconnect one before linking another."
                    )
                account_id = self._insert_account(account)
            else:
                account_id = int(existing["id"])
                self._update_account(account, account_id, int(existing["created_at"]))

        saved = self.get_account(account.owner_id, account_id)
        if saved is None:
            raise RuntimeError("Failed to save OAuth account.")
        return saved

    def get_accounts(self, owner_id: int) -> list[OAuthAccount]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT *
                FROM oauth_accounts
                WHERE owner_id = ?
                ORDER BY created_at ASC, id ASC
                """,
                (int(owner_id),),
            ).fetchall()

        return [_account_from_row(row) for row in rows]

    def get_account(
        self,
        owner_id: int,
        account_id: int | None = None,
    ) -> OAuthAccount | None:
        with self._lock:
            if account_id is None:
                row = self._connection.execute(
                    """
                    SELECT *
                    FROM oauth_accounts
                    WHERE owner_id = ?
                    ORDER BY created_at ASC, id ASC
                    LIMIT 1
                    """,
                    (int(owner_id),),
                ).fetchone()
            else:
                row = self._connection.execute(
                    """
                    SELECT *
                    FROM oauth_accounts
                    WHERE owner_id = ?
                      AND id = ?
                    """,
                    (int(owner_id), int(account_id)),
                ).fetchone()

        if row is None:
            return None
        return _account_from_row(row)

    def delete_account(
        self,
        owner_id: int,
        account_id: int | None = None,
    ) -> None:
        account = self.get_account(owner_id, account_id)
        if account is None or account.account_id is None:
            return

        with self._lock:
            self._connection.execute(
                "DELETE FROM oauth_accounts WHERE owner_id = ? AND id = ?",
                (int(owner_id), int(account.account_id)),
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

    def _find_existing_account_row(self, account: OAuthAccount) -> sqlite3.Row | None:
        if account.account_id is not None:
            row = self._connection.execute(
                """
                SELECT id, created_at
                FROM oauth_accounts
                WHERE owner_id = ?
                  AND id = ?
                """,
                (int(account.owner_id), int(account.account_id)),
            ).fetchone()
            if row is not None:
                return row

        return self._connection.execute(
            """
            SELECT id, created_at
            FROM oauth_accounts
            WHERE owner_id = ?
              AND discord_user_id = ?
            """,
            (int(account.owner_id), str(account.discord_user_id)),
        ).fetchone()

    def _account_count(self, owner_id: int) -> int:
        row = self._connection.execute(
            "SELECT COUNT(*) AS account_count FROM oauth_accounts WHERE owner_id = ?",
            (int(owner_id),),
        ).fetchone()
        return int(row["account_count"])

    def _insert_account(self, account: OAuthAccount) -> int:
        cursor = self._connection.execute(
            """
            INSERT INTO oauth_accounts (
                owner_id,
                discord_user_id,
                username,
                global_name,
                mfa_enabled,
                access_token,
                refresh_token,
                token_type,
                expires_at,
                scopes,
                ip_address,
                user_agent,
                created_at,
                updated_at,
                webhook_id,
                webhook_token,
                webhook_channel_id,
                webhook_guild_id,
                webhook_name
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            _account_values(account, account.created_at),
        )
        return int(cursor.lastrowid)

    def _update_account(
        self,
        account: OAuthAccount,
        account_id: int,
        created_at: int,
    ) -> None:
        self._connection.execute(
            """
            UPDATE oauth_accounts
            SET
                owner_id = ?,
                discord_user_id = ?,
                username = ?,
                global_name = ?,
                mfa_enabled = ?,
                access_token = ?,
                refresh_token = ?,
                token_type = ?,
                expires_at = ?,
                scopes = ?,
                ip_address = ?,
                user_agent = ?,
                created_at = ?,
                updated_at = ?,
                webhook_id = ?,
                webhook_token = ?,
                webhook_channel_id = ?,
                webhook_guild_id = ?,
                webhook_name = ?
            WHERE id = ?
              AND owner_id = ?
            """,
            (*_account_values(account, created_at), int(account_id), int(account.owner_id)),
        )

    def _migrate_oauth_accounts_primary_key(self) -> None:
        if "id" in self._column_names("oauth_accounts"):
            return

        self._connection.execute("ALTER TABLE oauth_accounts RENAME TO oauth_accounts_legacy")
        self._connection.execute(
            """
            CREATE TABLE oauth_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                discord_user_id TEXT NOT NULL,
                username TEXT,
                global_name TEXT,
                mfa_enabled INTEGER,
                access_token TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                token_type TEXT NOT NULL DEFAULT 'Bearer',
                expires_at INTEGER NOT NULL,
                scopes TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                webhook_id TEXT,
                webhook_token TEXT,
                webhook_channel_id TEXT,
                webhook_guild_id TEXT,
                webhook_name TEXT,
                UNIQUE(owner_id, discord_user_id)
            )
            """
        )
        self._connection.execute(
            """
            INSERT INTO oauth_accounts (
                owner_id,
                discord_user_id,
                username,
                global_name,
                mfa_enabled,
                access_token,
                refresh_token,
                token_type,
                expires_at,
                scopes,
                ip_address,
                user_agent,
                created_at,
                updated_at,
                webhook_id,
                webhook_token,
                webhook_channel_id,
                webhook_guild_id,
                webhook_name
            )
            SELECT
                owner_id,
                discord_user_id,
                username,
                global_name,
                mfa_enabled,
                access_token,
                refresh_token,
                token_type,
                expires_at,
                scopes,
                ip_address,
                user_agent,
                created_at,
                updated_at,
                webhook_id,
                webhook_token,
                webhook_channel_id,
                webhook_guild_id,
                webhook_name
            FROM oauth_accounts_legacy
            """
        )
        self._connection.execute("DROP TABLE oauth_accounts_legacy")

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        columns = {
            row["name"]
            for row in self._connection.execute(f"PRAGMA table_info({table})")
        }
        if column not in columns:
            self._connection.execute(
                f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
            )

    def _column_names(self, table: str) -> set[str]:
        return {
            row["name"]
            for row in self._connection.execute(f"PRAGMA table_info({table})")
        }


def _account_from_row(row: sqlite3.Row) -> OAuthAccount:
    return OAuthAccount(
        owner_id=int(row["owner_id"]),
        discord_user_id=str(row["discord_user_id"]),
        username=row["username"],
        global_name=row["global_name"],
        mfa_enabled=_int_to_bool(row["mfa_enabled"]),
        access_token=row["access_token"],
        refresh_token=row["refresh_token"],
        token_type=row["token_type"],
        expires_at=int(row["expires_at"]),
        scopes=scopes_from_json(row["scopes"]),
        ip_address=row["ip_address"],
        user_agent=row["user_agent"],
        created_at=int(row["created_at"]),
        updated_at=int(row["updated_at"]),
        account_id=int(row["id"]),
        webhook_id=row["webhook_id"],
        webhook_token=row["webhook_token"],
        webhook_channel_id=row["webhook_channel_id"],
        webhook_guild_id=row["webhook_guild_id"],
        webhook_name=row["webhook_name"],
    )


def _state_from_row(row: sqlite3.Row, used_count_offset: int = 0) -> OAuthState:
    return OAuthState(
        state=row["state"],
        owner_id=int(row["owner_id"]),
        scopes=scopes_from_json(row["scopes"]),
        created_at=int(row["created_at"]),
        expires_at=int(row["expires_at"]),
        use_limit=_optional_int(row["use_limit"]),
        used_count=int(row["used_count"] or 0) + used_count_offset,
    )


def _security_settings_from_row(row: sqlite3.Row) -> OwnerSecuritySettings:
    timeout_seconds = int(row["panel_timeout_seconds"] or DEFAULT_PANEL_TIMEOUT_SECONDS)
    return OwnerSecuritySettings(
        owner_id=int(row["owner_id"]),
        password_hash=row["password_hash"],
        encryption_enabled=bool(row["encryption_enabled"]),
        panel_timeout_seconds=timeout_seconds,
        updated_at=int(row["updated_at"] or 0),
    )


def _account_values(account: OAuthAccount, created_at: int) -> tuple:
    return (
        account.owner_id,
        account.discord_user_id,
        account.username,
        account.global_name,
        _bool_to_int(account.mfa_enabled),
        account.access_token,
        account.refresh_token,
        account.token_type,
        account.expires_at,
        scopes_to_json(account.scopes),
        account.ip_address,
        account.user_agent,
        int(created_at),
        account.updated_at,
        account.webhook_id,
        account.webhook_token,
        account.webhook_channel_id,
        account.webhook_guild_id,
        account.webhook_name,
    )


def _now() -> int:
    return int(time.time())


def _bool_to_int(value: bool | None) -> int | None:
    if value is None:
        return None
    return 1 if value else 0


def _int_to_bool(value: int | None) -> bool | None:
    if value is None:
        return None
    return bool(value)


def _optional_int(value: int | None) -> int | None:
    if value is None:
        return None
    return int(value)
