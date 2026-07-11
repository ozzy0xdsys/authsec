from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import discord

from .models import (
    DEFAULT_OAUTH_LINK_TTL_SECONDS,
    DEFAULT_OAUTH_LINK_USE_LIMIT,
    MAX_ACCOUNTS_PER_OWNER,
    OAUTH_LINK_TTL_OPTIONS,
    OAUTH_LINK_USE_LIMIT_OPTIONS,
    PANEL_TIMEOUT_OPTIONS,
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    OAuthAccount,
    OwnerSecuritySettings,
)
from .oauth import DiscordApiError, DiscordOAuthClient


ACCENT_DEFAULT = discord.Color.blurple()
ACCENT_SUCCESS = discord.Color.green()
ACCENT_ERROR = discord.Color.red()
ACCENT_MUTED = discord.Color.dark_theme()


COLOR_NAMES = {
    "blue": discord.Color.blue(),
    "blurple": discord.Color.blurple(),
    "green": discord.Color.green(),
    "red": discord.Color.red(),
    "orange": discord.Color.orange(),
    "yellow": discord.Color.yellow(),
    "purple": discord.Color.purple(),
    "dark": discord.Color.dark_theme(),
}


DEFAULT_SETUP_SCOPES = [
    "email",
    "guilds",
    "connections",
    "relationships.read",
]


SCOPE_LABELS = {
    "identify": "Identify",
    "email": "Email",
    "guilds": "Guilds",
    "guilds.members.read": "Guild Join Dates",
    "connections": "Connections",
    "guilds.join": "Join Guilds",
    "relationships.read": "Relationships",
    "applications.builds.read": "App Builds",
    "gdm.join": "Group DM Join",
    "messages.read": "Messages Read",
    "webhook.incoming": "Incoming Webhook",
}


class TextContainerView(discord.ui.LayoutView):
    def __init__(
        self,
        title: str,
        body: str,
        accent_color: discord.Color = ACCENT_DEFAULT,
        timeout: float | None = None,
    ):
        super().__init__(timeout=timeout)
        self.add_item(
            discord.ui.Container(
                discord.ui.TextDisplay(f"## {title}\n{body}"),
                accent_color=accent_color,
            )
        )


class AccessRequiredView(discord.ui.LayoutView):
    def __init__(self, url: str):
        super().__init__(timeout=None)
        self.add_item(
            discord.ui.Container(
                discord.ui.TextDisplay(
                    "## Access check required\n"
                    "You can't use this bot until you complete the access check."
                ),
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(
                    discord.ui.Button(
                        label="Gain access",
                        style=discord.ButtonStyle.link,
                        url=url,
                    )
                ),
                accent_color=ACCENT_ERROR,
            )
        )


def build_admin_access_check_view(user_id: int | str, url: str) -> discord.ui.LayoutView:
    view = discord.ui.LayoutView(timeout=None)
    view.add_item(
        discord.ui.Container(
            discord.ui.TextDisplay(
                "## Access check created\n"
                f"User: <@{user_id}> (`{user_id}`)\n\n"
                f"`{url}`"
            ),
            discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
            discord.ui.ActionRow(
                discord.ui.Button(
                    label="Gain access",
                    style=discord.ButtonStyle.link,
                    url=url,
                )
            ),
            accent_color=ACCENT_DEFAULT,
        )
    )
    return view


class SetupScopeView(discord.ui.LayoutView):
    def __init__(self, oauth_client: DiscordOAuthClient, owner_id: int):
        super().__init__(timeout=300)
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.selected_scopes = list(DEFAULT_SETUP_SCOPES)
        self.link_ttl_seconds = DEFAULT_OAUTH_LINK_TTL_SECONDS
        self.link_use_limit = DEFAULT_OAUTH_LINK_USE_LIMIT
        self.add_item(
            discord.ui.Container(
                discord.ui.TextDisplay(
                    "## Set up OAuth\n"
                    "Choose the account access to request. The default options cover "
                    "the main panel buttons. `Identify` is always included so the app "
                    "knows which Discord account authorized it. You can store up to "
                    f"{MAX_ACCOUNTS_PER_OWNER} accounts; re-authorizing the same "
                    "account updates its saved access.\n\n"
                    "Choose how long the authorization link works and how many times "
                    "it can successfully link an account."
                ),
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(ScopeSelect(self)),
                discord.ui.ActionRow(LinkDurationSelect(self)),
                discord.ui.ActionRow(LinkUseLimitSelect(self)),
                discord.ui.ActionRow(GenerateLinkButton(self)),
                accent_color=ACCENT_DEFAULT,
            )
        )

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.owner_id:
            return True

        await interaction.response.send_message(
            view=build_error_view("This setup menu belongs to someone else."),
            ephemeral=True,
        )
        return False


class ScopeSelect(discord.ui.Select):
    def __init__(self, parent: SetupScopeView):
        options = oauth_scope_options()
        super().__init__(
            placeholder="Choose account access",
            min_values=0,
            max_values=len(options),
            options=options,
        )
        self.parent_view = parent

    async def callback(self, interaction: discord.Interaction):
        self.parent_view.selected_scopes = list(self.values)
        await interaction.response.defer()


class LinkDurationSelect(discord.ui.Select):
    def __init__(self, parent: SetupScopeView):
        self.parent_view = parent
        super().__init__(
            placeholder="Authorization link expires after",
            min_values=1,
            max_values=1,
            options=[
                discord.SelectOption(
                    label=format_oauth_link_ttl_label(seconds),
                    value=str(seconds),
                    default=seconds == parent.link_ttl_seconds,
                )
                for seconds in OAUTH_LINK_TTL_OPTIONS
            ],
        )

    async def callback(self, interaction: discord.Interaction):
        self.parent_view.link_ttl_seconds = int(self.values[0])
        await interaction.response.defer()


class LinkUseLimitSelect(discord.ui.Select):
    def __init__(self, parent: SetupScopeView):
        self.parent_view = parent
        super().__init__(
            placeholder="Authorization link uses allowed",
            min_values=1,
            max_values=1,
            options=[
                discord.SelectOption(
                    label=format_oauth_link_use_label(limit),
                    value=str(limit),
                    default=limit == parent.link_use_limit,
                )
                for limit in OAUTH_LINK_USE_LIMIT_OPTIONS
            ],
        )

    async def callback(self, interaction: discord.Interaction):
        self.parent_view.link_use_limit = int(self.values[0])
        await interaction.response.defer()


class GenerateLinkButton(discord.ui.Button):
    def __init__(self, parent: SetupScopeView):
        super().__init__(
            label="Create OAuth Link",
            style=discord.ButtonStyle.primary,
        )
        self.parent_view = parent

    async def callback(self, interaction: discord.Interaction):
        try:
            url = await asyncio.to_thread(
                self.parent_view.oauth_client.build_authorization_url,
                self.parent_view.owner_id,
                self.parent_view.selected_scopes,
                self.parent_view.link_ttl_seconds,
                self.parent_view.link_use_limit,
            )
        except DiscordApiError as exc:
            await interaction.response.send_message(
                view=build_error_view(str(exc)),
                ephemeral=True,
            )
            return

        scopes = [*self.parent_view.selected_scopes, "identify"]
        await interaction.response.send_message(
            view=GeneratedOAuthLinkView(
                url,
                scopes,
                self.parent_view.link_ttl_seconds,
                self.parent_view.link_use_limit,
            ),
            ephemeral=True,
        )


class GeneratedOAuthLinkView(discord.ui.LayoutView):
    def __init__(
        self,
        url: str,
        scopes: list[str],
        ttl_seconds: int,
        use_limit: int,
    ):
        super().__init__(timeout=None)
        self.url = url
        self.scopes = scopes
        self.ttl_seconds = int(ttl_seconds)
        self.use_limit = int(use_limit)
        expires_at = int(time.time()) + self.ttl_seconds
        self.add_item(
            discord.ui.Container(
                discord.ui.TextDisplay(
                    "## Authorization Link Ready\n"
                    "Open this link to authorize the selected access.\n\n"
                    f"**Expires:** <t:{expires_at}:R>\n"
                    f"**Uses:** {format_oauth_link_use_label(self.use_limit)}\n"
                    f"**Access:** {format_scope_list(scopes)}\n\n"
                    f"`{url}`"
                ),
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(
                    discord.ui.Button(
                        label="Authorize",
                        style=discord.ButtonStyle.link,
                        url=url,
                    ),
                    PostOAuthButton(self),
                ),
                accent_color=ACCENT_SUCCESS,
            )
        )


class PostOAuthButton(discord.ui.Button):
    def __init__(self, parent: GeneratedOAuthLinkView):
        super().__init__(
            label="Post Button Here",
            style=discord.ButtonStyle.primary,
        )
        self.parent_view = parent

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.send_message(
            view=PublicOAuthButtonView(
                title="Authorize with Discord",
                description="Use the button below to authorize the requested account access.",
                url=self.parent_view.url,
                accent_color=ACCENT_DEFAULT,
            )
        )


class PublicOAuthButtonView(discord.ui.LayoutView):
    def __init__(
        self,
        title: str,
        description: str,
        url: str,
        accent_color: discord.Color,
    ):
        super().__init__(timeout=None)
        self.add_item(
            discord.ui.Container(
                discord.ui.TextDisplay(f"## {title}\n{description}"),
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(
                    discord.ui.Button(
                        label="Authorize",
                        style=discord.ButtonStyle.link,
                        url=url,
                    )
                ),
                accent_color=accent_color,
            )
        )


class CreateOAuthButtonModal(discord.ui.Modal, title="OAuth Button"):
    def __init__(self):
        super().__init__()
        self.title_input = discord.ui.TextInput(
            label="Title",
            placeholder="Authorization required",
            max_length=120,
        )
        self.description_input = discord.ui.TextInput(
            label="Description",
            placeholder="Click the button below to authorize with Discord.",
            style=discord.TextStyle.paragraph,
            max_length=1000,
        )
        self.link_input = discord.ui.TextInput(
            label="OAuth Link",
            placeholder="https://discord.com/oauth2/authorize?...",
            max_length=1000,
        )
        self.color_input = discord.ui.TextInput(
            label="Color",
            placeholder="blue, green, red, purple, dark, or #5865F2",
            required=False,
            max_length=20,
        )
        self.add_item(self.title_input)
        self.add_item(self.description_input)
        self.add_item(self.link_input)
        self.add_item(self.color_input)

    async def on_submit(self, interaction: discord.Interaction):
        link = self.link_input.value.strip()
        if not _is_discord_oauth_url(link):
            await interaction.response.send_message(
                view=build_error_view("Please provide a Discord OAuth2 authorization URL."),
                ephemeral=True,
            )
            return

        await interaction.response.send_message(
            view=PublicOAuthButtonView(
                title=self.title_input.value.strip(),
                description=self.description_input.value.strip(),
                url=link,
                accent_color=parse_color(self.color_input.value),
            )
        )


class PanelUnlockModal(discord.ui.Modal, title="Unlock Panel"):
    def __init__(self, oauth_client: DiscordOAuthClient, owner_id: int):
        super().__init__()
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.password_input = password_text_input("Password")
        self.add_item(encryption_unlock_notice())
        self.add_item(self.password_input)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            await asyncio.to_thread(
                self.oauth_client.unlock_owner,
                self.owner_id,
                str(self.password_input.value),
            )
            note = "Encryption unlocked for this panel session."
            try:
                accounts = await asyncio.to_thread(
                    self.oauth_client.get_accounts,
                    self.owner_id,
                    True,
                )
            except DiscordApiError as exc:
                accounts = await asyncio.to_thread(
                    self.oauth_client.get_accounts,
                    self.owner_id,
                    False,
                )
                note = f"{note} {exc}"
            view = PanelView(
                self.oauth_client,
                self.owner_id,
                accounts,
                can_join_here=bot_has_admin_in_interaction(interaction),
                note=note,
            )
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        message = await interaction.followup.send(
            view=view,
            ephemeral=True,
            wait=True,
        )
        if isinstance(view, PanelView):
            view.bind_message(message)


class SetupUnlockModal(discord.ui.Modal, title="Unlock Setup"):
    def __init__(self, oauth_client: DiscordOAuthClient, owner_id: int):
        super().__init__()
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.password_input = password_text_input("Password")
        self.add_item(encryption_unlock_notice())
        self.add_item(self.password_input)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            await asyncio.to_thread(
                self.oauth_client.unlock_owner,
                self.owner_id,
                str(self.password_input.value),
            )
            view = SetupScopeView(self.oauth_client, self.owner_id)
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        await interaction.response.send_message(view=view, ephemeral=True)


class EncryptionSettingsView(discord.ui.LayoutView):
    def __init__(
        self,
        oauth_client: DiscordOAuthClient,
        owner_id: int,
        note: str | None = None,
    ):
        super().__init__(timeout=300)
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.settings = oauth_client.get_security_settings(owner_id)
        enabled = oauth_client.is_encryption_enabled(owner_id)

        buttons: list[discord.ui.Item] = []
        if enabled:
            buttons.append(DisableEncryptionButton(self))
        else:
            buttons.append(EnableEncryptionButton(self))

        self.add_item(
            discord.ui.Container(
                discord.ui.TextDisplay(
                    encryption_settings_text(
                        oauth_client,
                        self.owner_id,
                        self.settings,
                        note,
                    )
                ),
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(*buttons),
                discord.ui.ActionRow(PanelTimeoutSelect(self)),
                accent_color=ACCENT_SUCCESS if enabled else ACCENT_DEFAULT,
            )
        )

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.owner_id:
            return True

        await interaction.response.send_message(
            view=build_error_view("This encryption menu belongs to someone else."),
            ephemeral=True,
        )
        return False


class EnableEncryptionButton(discord.ui.Button):
    def __init__(self, parent: EncryptionSettingsView):
        super().__init__(
            label="Enable Encryption",
            style=discord.ButtonStyle.success,
        )
        self.parent_view = parent

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.send_modal(
            EnableEncryptionModal(
                self.parent_view.oauth_client,
                self.parent_view.owner_id,
            )
        )


class DisableEncryptionButton(discord.ui.Button):
    def __init__(self, parent: EncryptionSettingsView):
        super().__init__(
            label="Disable Encryption",
            style=discord.ButtonStyle.danger,
        )
        self.parent_view = parent

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.send_modal(
            DisableEncryptionModal(
                self.parent_view.oauth_client,
                self.parent_view.owner_id,
            )
        )


class PanelTimeoutSelect(discord.ui.Select):
    def __init__(self, parent: EncryptionSettingsView):
        self.parent_view = parent
        current = parent.oauth_client.panel_timeout_seconds(parent.owner_id)
        super().__init__(
            placeholder="Panel buttons disable after",
            min_values=1,
            max_values=1,
            options=[
                discord.SelectOption(
                    label=format_timeout_label(seconds),
                    value=str(seconds),
                    description="How long an unlocked /panel message stays clickable.",
                    default=seconds == current,
                )
                for seconds in PANEL_TIMEOUT_OPTIONS
            ],
        )

    async def callback(self, interaction: discord.Interaction):
        settings = await asyncio.to_thread(
            self.parent_view.oauth_client.set_panel_timeout,
            self.parent_view.owner_id,
            int(self.values[0]),
        )
        await interaction.response.edit_message(
            view=EncryptionSettingsView(
                self.parent_view.oauth_client,
                self.parent_view.owner_id,
                note=f"Panel buttons now time out after {format_timeout_label(settings.panel_timeout_seconds)}.",
            )
        )


class EnableEncryptionModal(discord.ui.Modal, title="Enable Encryption"):
    def __init__(self, oauth_client: DiscordOAuthClient, owner_id: int):
        super().__init__()
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.password_input = password_text_input("Password")
        self.confirm_input = password_text_input("Confirm Password")
        self.add_item(self.password_input)
        self.add_item(self.confirm_input)

    async def on_submit(self, interaction: discord.Interaction):
        password = str(self.password_input.value)
        confirm = str(self.confirm_input.value)
        if password != confirm:
            await interaction.response.send_message(
                view=build_error_view("The passwords did not match."),
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            await asyncio.to_thread(
                self.oauth_client.enable_encryption,
                self.owner_id,
                password,
            )
            view = EncryptionSettingsView(
                self.oauth_client,
                self.owner_id,
                note="Encryption enabled. Saved tokens, IP addresses, user agents, and webhook tokens were encrypted.",
            )
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        await interaction.followup.send(view=view, ephemeral=True)


class DisableEncryptionModal(discord.ui.Modal, title="Disable Encryption"):
    def __init__(self, oauth_client: DiscordOAuthClient, owner_id: int):
        super().__init__()
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.password_input = password_text_input("Password")
        self.add_item(self.password_input)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            await asyncio.to_thread(
                self.oauth_client.disable_encryption,
                self.owner_id,
                str(self.password_input.value),
            )
            view = EncryptionSettingsView(
                self.oauth_client,
                self.owner_id,
                note="Encryption disabled. Saved sensitive values were decrypted back into the database.",
            )
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        await interaction.followup.send(view=view, ephemeral=True)


class PanelView(discord.ui.LayoutView):
    def __init__(
        self,
        oauth_client: DiscordOAuthClient,
        owner_id: int,
        accounts: list[OAuthAccount],
        can_join_here: bool,
        note: str | None = None,
        page: int = 0,
        expires_at: int | None = None,
    ):
        timeout_seconds = oauth_client.panel_timeout_seconds(owner_id)
        self.expires_at = expires_at or int(time.time()) + timeout_seconds
        remaining_seconds = max(1, self.expires_at - int(time.time()))
        super().__init__(timeout=remaining_seconds)
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.accounts = accounts
        self.page = panel_page_index(accounts, page)
        self.account = accounts[self.page] if accounts else None
        self.account_id = self.account.account_id if self.account else None
        self.can_join_here = can_join_here
        self.message: Any = None
        has_account = self.account is not None

        self.add_item(account_switcher_container(self))

        children: list[discord.ui.Item] = [
            discord.ui.TextDisplay(
                panel_text(
                    self.account,
                    note,
                    self.expires_at,
                    timeout_seconds,
                )
            ),
            discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
            discord.ui.ActionRow(
                RefreshButton(self, disabled=not has_account),
                DetailsButton(self, disabled=not has_account),
                GuildsButton(
                    self,
                    disabled=not has_account or not self.account.has_scope("guilds"),
                ),
                ConnectionsButton(
                    self,
                    disabled=not has_account
                    or not self.account.has_scope("connections"),
                ),
            ),
            discord.ui.ActionRow(
                RelationshipsButton(
                    self,
                    disabled=not has_account
                    or not self.account.has_scope("relationships.read"),
                ),
                WebhookMessageButton(
                    self,
                    disabled=(
                        not has_account
                        or not self.account.has_scope("webhook.incoming")
                    ),
                ),
                JoinServerButton(
                    self,
                    disabled=(
                        not has_account
                        or not self.account.has_scope("guilds.join")
                        or not can_join_here
                    ),
                ),
                DisconnectButton(self, disabled=not has_account),
            ),
        ]

        self.add_item(
            discord.ui.Container(
                *children,
                accent_color=ACCENT_DEFAULT if has_account else ACCENT_MUTED,
            )
        )

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.owner_id:
            if self.is_expired:
                self.disable_interactive_items()
                await interaction.response.edit_message(view=self)
                return False
            return True

        await interaction.response.send_message(
            view=build_error_view("This panel belongs to someone else."),
            ephemeral=True,
        )
        return False

    @property
    def is_expired(self) -> bool:
        return int(time.time()) >= self.expires_at

    def bind_message(self, message: Any) -> None:
        self.message = message

    def disable_interactive_items(self) -> None:
        for item in self.walk_children():
            if hasattr(item, "disabled"):
                item.disabled = True

    async def on_timeout(self) -> None:
        self.disable_interactive_items()
        if self.message is None:
            return
        try:
            await self.message.edit(view=self)
        except discord.HTTPException:
            pass


class AccountSwitchButton(discord.ui.Button):
    def __init__(self, panel: PanelView, account: OAuthAccount, page: int):
        self.panel = panel
        self.page = page
        super().__init__(
            label=account_switch_label(account, page),
            style=(
                discord.ButtonStyle.primary
                if page == panel.page
                else discord.ButtonStyle.secondary
            ),
            disabled=page == panel.page,
        )

    async def callback(self, interaction: discord.Interaction):
        view = PanelView(
            self.panel.oauth_client,
            self.panel.owner_id,
            self.panel.accounts,
            can_join_here=bot_has_admin_in_interaction(interaction),
            page=self.page,
            expires_at=self.panel.expires_at,
        )
        view.bind_message(self.panel.message)
        await interaction.response.edit_message(
            view=view
        )
        self.panel.stop()


class AccountSelect(discord.ui.Select):
    def __init__(self, panel: PanelView):
        self.panel = panel
        super().__init__(
            placeholder="Choose saved account",
            min_values=1,
            max_values=1,
            options=[
                discord.SelectOption(
                    label=account_select_label(account),
                    value=account_select_value(account, index),
                    description=account_select_description(account, index),
                    default=index == panel.page,
                )
                for index, account in enumerate(panel.accounts)
            ],
        )

    async def callback(self, interaction: discord.Interaction):
        view = PanelView(
            self.panel.oauth_client,
            self.panel.owner_id,
            self.panel.accounts,
            can_join_here=bot_has_admin_in_interaction(interaction),
            page=panel_page_for_value(
                self.panel.accounts,
                self.values[0],
                self.panel.page,
            ),
            expires_at=self.panel.expires_at,
        )
        view.bind_message(self.panel.message)
        await interaction.response.edit_message(
            view=view
        )
        self.panel.stop()


class RefreshButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Refresh",
            style=discord.ButtonStyle.primary,
            disabled=disabled,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer()
        account_id = self.panel.account_id
        try:
            refreshed = await asyncio.to_thread(
                self.panel.oauth_client.refresh_account,
                self.panel.owner_id,
                True,
                account_id,
            )
            account_id = refreshed.account_id
            note = "Token refreshed. Account metadata was updated from Discord."
        except DiscordApiError as exc:
            note = str(exc)

        accounts = await asyncio.to_thread(
            self.panel.oauth_client.get_accounts,
            self.panel.owner_id,
            False,
        )
        view = PanelView(
            self.panel.oauth_client,
            self.panel.owner_id,
            accounts,
            can_join_here=bot_has_admin_in_interaction(interaction),
            note=note,
            page=panel_page_for_account(accounts, account_id, self.panel.page),
            expires_at=self.panel.expires_at,
        )
        message = await interaction.edit_original_response(
            view=view
        )
        view.bind_message(message)
        self.panel.stop()


class DetailsButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Details",
            style=discord.ButtonStyle.secondary,
            disabled=disabled,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            user = await asyncio.to_thread(
                self.panel.oauth_client.fetch_current_user,
                self.panel.owner_id,
                self.panel.account_id,
            )
            view = build_user_view(
                user,
                self.panel.account,
                self.panel.oauth_client,
                self.panel.owner_id,
            )
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        await interaction.followup.send(view=view, ephemeral=True)


class IPInfoButton(discord.ui.Button):
    def __init__(
        self,
        oauth_client: DiscordOAuthClient,
        owner_id: int | None,
        ip_address: str | None,
    ):
        super().__init__(
            label="IP Info",
            style=discord.ButtonStyle.secondary,
            disabled=not bool(str(ip_address or "").strip()),
        )
        self.oauth_client = oauth_client
        self.owner_id = owner_id
        self.ip_address = ip_address

    async def callback(self, interaction: discord.Interaction):
        if self.owner_id is not None and interaction.user.id != self.owner_id:
            await interaction.response.send_message(
                view=build_error_view("This account detail view belongs to someone else."),
                ephemeral=True,
            )
            return

        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            payload = await asyncio.to_thread(
                self.oauth_client.fetch_ip_info,
                self.ip_address,
            )
            view = build_ip_info_view(payload)
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        await interaction.followup.send(view=view, ephemeral=True)


class GuildsButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Guilds",
            style=discord.ButtonStyle.secondary,
            disabled=disabled,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            guilds = await asyncio.to_thread(
                self.panel.oauth_client.fetch_guilds,
                self.panel.owner_id,
                self.panel.account_id,
            )
            member_details = await fetch_guild_page_member_details(
                self.panel.oauth_client,
                self.panel.owner_id,
                guilds,
                0,
                self.panel.account,
                self.panel.account_id,
            )
            view = GuildsPageView(
                guilds,
                self.panel.owner_id,
                self.panel.oauth_client,
                member_details=member_details,
                can_show_join_dates=can_show_guild_join_dates(self.panel.account),
                account_id=self.panel.account_id,
            )
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        await interaction.followup.send(view=view, ephemeral=True)


class ConnectionsButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Connections",
            style=discord.ButtonStyle.secondary,
            disabled=disabled,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            connections = await asyncio.to_thread(
                self.panel.oauth_client.fetch_connections,
                self.panel.owner_id,
                self.panel.account_id,
            )
            view = build_list_view("Linked Connections", connections, "connection")
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        await interaction.followup.send(view=view, ephemeral=True)


class RelationshipsButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Relationships",
            style=discord.ButtonStyle.secondary,
            disabled=disabled,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            relationships = await asyncio.to_thread(
                self.panel.oauth_client.fetch_relationships,
                self.panel.owner_id,
                self.panel.account_id,
            )
            view = RelationshipsPageView(relationships, self.panel.owner_id)
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        await interaction.followup.send(view=view, ephemeral=True)


class WebhookMessageButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Webhook",
            style=discord.ButtonStyle.secondary,
            disabled=disabled,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        if self.panel.account is not None and not self.panel.account.has_webhook:
            await interaction.response.send_message(
                view=build_error_view(
                    "No OAuth webhook was stored for this account. Generate a new "
                    "OAuth link with Incoming Webhook selected and authorize it again."
                ),
                ephemeral=True,
            )
            return

        await interaction.response.send_modal(
            WebhookMessageModal(
                self.panel.oauth_client,
                self.panel.owner_id,
                self.panel.account_id,
            )
        )


class WebhookMessageModal(discord.ui.Modal, title="Webhook Message"):
    def __init__(
        self,
        oauth_client: DiscordOAuthClient,
        owner_id: int,
        account_id: int | None,
    ):
        super().__init__()
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.account_id = account_id
        self.content_input = discord.ui.TextInput(
            label="Message",
            placeholder="Text to send through the OAuth webhook.",
            style=discord.TextStyle.paragraph,
            max_length=2000,
        )
        self.username_input = discord.ui.TextInput(
            label="Webhook Username",
            placeholder="Optional display name for this message.",
            required=False,
            max_length=80,
        )
        self.add_item(self.content_input)
        self.add_item(self.username_input)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            message = await asyncio.to_thread(
                self.oauth_client.send_webhook_message,
                self.owner_id,
                str(self.content_input.value),
                str(self.username_input.value or ""),
                self.account_id,
            )
            view = TextContainerView("Webhook Sent", message, ACCENT_SUCCESS)
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        await interaction.response.send_message(view=view, ephemeral=True)


class JoinServerButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Join Server",
            style=discord.ButtonStyle.success,
            disabled=disabled,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        if interaction.guild is None:
            await interaction.response.send_message(
                view=build_error_view("Run this from a server to use guild joining."),
                ephemeral=True,
            )
            return

        if not bot_has_admin_in_interaction(interaction):
            await interaction.response.send_message(
                view=build_error_view("This server is not available for joining."),
                ephemeral=True,
            )
            return

        await interaction.response.send_message(
            view=JoinServerConfirmView(
                self.panel.oauth_client,
                self.panel.owner_id,
                self.panel.account_id,
                interaction.guild.id,
                interaction.guild.name,
            ),
            ephemeral=True,
        )


class JoinServerConfirmView(discord.ui.LayoutView):
    def __init__(
        self,
        oauth_client: DiscordOAuthClient,
        owner_id: int,
        account_id: int | None,
        guild_id: int,
        guild_name: str,
    ):
        super().__init__(timeout=120)
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.account_id = account_id
        self.guild_id = int(guild_id)
        self.guild_name = guild_name
        self.add_item(
            discord.ui.Container(
                discord.ui.TextDisplay(
                    "## Confirm Server Join\n"
                    f"You are about to add the linked account to **{guild_name}**.\n\n"
                    "Discord will send the linked account a DM that the bot made them"
                    "join a server"
                ),
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(
                    ConfirmJoinServerButton(self),
                    CancelJoinServerButton(),
                ),
                accent_color=ACCENT_DEFAULT,
            )
        )

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.owner_id:
            return True

        await interaction.response.send_message(
            view=build_error_view("This confirmation belongs to someone else."),
            ephemeral=True,
        )
        return False


class ConfirmJoinServerButton(discord.ui.Button):
    def __init__(self, confirm_view: JoinServerConfirmView):
        super().__init__(
            label="Confirm Join",
            style=discord.ButtonStyle.success,
        )
        self.confirm_view = confirm_view

    async def callback(self, interaction: discord.Interaction):
        if not bot_has_admin_in_interaction(interaction):
            await interaction.response.edit_message(
                view=build_error_view("This server is not available for joining.")
            )
            return

        await interaction.response.defer()
        try:
            message = await asyncio.to_thread(
                self.confirm_view.oauth_client.add_to_guild,
                self.confirm_view.owner_id,
                self.confirm_view.guild_id,
                self.confirm_view.account_id,
            )
            view = TextContainerView("Join complete", message, ACCENT_SUCCESS)
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        await interaction.edit_original_response(view=view)


class CancelJoinServerButton(discord.ui.Button):
    def __init__(self):
        super().__init__(
            label="Cancel",
            style=discord.ButtonStyle.secondary,
        )

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.edit_message(
            view=TextContainerView(
                "Join cancelled",
                "No action was taken.",
                ACCENT_MUTED,
            )
        )


class DisconnectButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Disconnect",
            style=discord.ButtonStyle.danger,
            disabled=disabled,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer()
        account_id = self.panel.account_id
        revoked = await asyncio.to_thread(
            self.panel.oauth_client.disconnect_account,
            self.panel.owner_id,
            account_id,
        )
        accounts = await asyncio.to_thread(
            self.panel.oauth_client.get_accounts,
            self.panel.owner_id,
            False,
        )
        note = "Disconnected and revoked with Discord." if revoked else "Disconnected locally."
        view = PanelView(
            self.panel.oauth_client,
            self.panel.owner_id,
            accounts,
            can_join_here=bot_has_admin_in_interaction(interaction),
            note=note,
            page=panel_page_index(accounts, self.panel.page),
            expires_at=self.panel.expires_at,
        )
        message = await interaction.edit_original_response(view=view)
        view.bind_message(message)
        self.panel.stop()


class GuildsPageView(discord.ui.LayoutView):
    page_size = 2

    def __init__(
        self,
        guilds: list[dict[str, Any]],
        owner_id: int,
        oauth_client: DiscordOAuthClient | None = None,
        page: int = 0,
        member_details: dict[str, dict[str, Any]] | None = None,
        can_show_join_dates: bool = False,
        account_id: int | None = None,
    ):
        super().__init__(timeout=300)
        self.guilds = guilds
        self.owner_id = int(owner_id)
        self.oauth_client = oauth_client
        self.page = max(0, min(page, self.max_page))
        self.member_details = member_details or {}
        self.can_show_join_dates = can_show_join_dates
        self.account_id = account_id

        if not guilds:
            self.add_item(
                discord.ui.Container(
                    discord.ui.TextDisplay("## Linked Account Guilds\nNo guilds were returned."),
                    accent_color=ACCENT_MUTED,
                )
            )
            return

        children: list[discord.ui.Item] = [
            discord.ui.TextDisplay(
                f"## Linked Account Guilds\nPage {self.page + 1} of {self.max_page + 1}"
            ),
            discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
        ]

        for index, guild in enumerate(self.current_guilds):
            guild_id = str(guild.get("id", ""))
            children.append(guild_section(guild, self.member_details.get(guild_id)))
            if index < len(self.current_guilds) - 1:
                children.append(discord.ui.Separator(spacing=discord.SeparatorSpacing.small))

        children.extend(
            [
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(
                    GuildPageButton(self, -1),
                    GuildPageButton(self, 1),
                ),
            ]
        )

        self.add_item(
            discord.ui.Container(
                *children,
                accent_color=ACCENT_DEFAULT,
            )
        )

    @property
    def current_guilds(self) -> list[dict[str, Any]]:
        start = self.page * self.page_size
        return self.guilds[start : start + self.page_size]

    @property
    def max_page(self) -> int:
        if not self.guilds:
            return 0
        return (len(self.guilds) - 1) // self.page_size

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.owner_id:
            return True

        await interaction.response.send_message(
            view=build_error_view("This guild list belongs to someone else."),
            ephemeral=True,
        )
        return False


class GuildPageButton(discord.ui.Button):
    def __init__(self, guilds_view: GuildsPageView, direction: int):
        self.guilds_view = guilds_view
        self.direction = direction
        label = "Previous" if direction < 0 else "Next"
        disabled = (
            guilds_view.page <= 0 if direction < 0 else guilds_view.page >= guilds_view.max_page
        )
        super().__init__(
            label=label,
            style=discord.ButtonStyle.secondary,
            disabled=disabled,
        )

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer()
        next_page = self.guilds_view.page + self.direction
        member_details = {}
        if self.guilds_view.can_show_join_dates and self.guilds_view.oauth_client:
            member_details = await fetch_guild_page_member_details(
                self.guilds_view.oauth_client,
                self.guilds_view.owner_id,
                self.guilds_view.guilds,
                next_page,
                account_id=self.guilds_view.account_id,
            )

        await interaction.edit_original_response(
            view=GuildsPageView(
                self.guilds_view.guilds,
                self.guilds_view.owner_id,
                self.guilds_view.oauth_client,
                page=next_page,
                member_details=member_details,
                can_show_join_dates=self.guilds_view.can_show_join_dates,
                account_id=self.guilds_view.account_id,
            )
        )


class RelationshipsPageView(discord.ui.LayoutView):
    page_size = 2

    def __init__(
        self,
        relationships: list[dict[str, Any]],
        owner_id: int,
        page: int = 0,
    ):
        super().__init__(timeout=300)
        self.relationships = relationships
        self.owner_id = int(owner_id)
        self.page = max(0, min(page, self.max_page))

        if not relationships:
            self.add_item(
                discord.ui.Container(
                    discord.ui.TextDisplay("## Linked Relationships\nNo relationships were returned."),
                    accent_color=ACCENT_MUTED,
                )
            )
            return

        children: list[discord.ui.Item] = [
            discord.ui.TextDisplay(
                f"## Linked Relationships\nPage {self.page + 1} of {self.max_page + 1}"
            ),
            discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
        ]

        for index, relationship in enumerate(self.current_relationships):
            children.append(relationship_section(relationship))
            if index < len(self.current_relationships) - 1:
                children.append(discord.ui.Separator(spacing=discord.SeparatorSpacing.small))

        children.extend(
            [
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(
                    RelationshipPageButton(self, -1),
                    RelationshipPageButton(self, 1),
                ),
            ]
        )

        self.add_item(
            discord.ui.Container(
                *children,
                accent_color=ACCENT_DEFAULT,
            )
        )

    @property
    def current_relationships(self) -> list[dict[str, Any]]:
        start = self.page * self.page_size
        return self.relationships[start : start + self.page_size]

    @property
    def max_page(self) -> int:
        if not self.relationships:
            return 0
        return (len(self.relationships) - 1) // self.page_size

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.owner_id:
            return True

        await interaction.response.send_message(
            view=build_error_view("This relationship list belongs to someone else."),
            ephemeral=True,
        )
        return False


class RelationshipPageButton(discord.ui.Button):
    def __init__(self, relationships_view: RelationshipsPageView, direction: int):
        self.relationships_view = relationships_view
        self.direction = direction
        label = "Previous" if direction < 0 else "Next"
        disabled = (
            relationships_view.page <= 0
            if direction < 0
            else relationships_view.page >= relationships_view.max_page
        )
        super().__init__(
            label=label,
            style=discord.ButtonStyle.secondary,
            disabled=disabled,
        )

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.edit_message(
            view=RelationshipsPageView(
                self.relationships_view.relationships,
                self.relationships_view.owner_id,
                self.relationships_view.page + self.direction,
            )
        )


def oauth_scope_options() -> list[discord.SelectOption]:
    return [
        discord.SelectOption(
            label="Email",
            value="email",
            description="Show the linked account email when Discord returns it.",
            default=True,
        ),
        discord.SelectOption(
            label="Guilds",
            value="guilds",
            description="Allow /panel to list the linked account servers.",
            default=True,
        ),
        discord.SelectOption(
            label="Guild Join Dates",
            value="guilds.members.read",
            description="Show when the linked account joined each server.",
        ),
        discord.SelectOption(
            label="Connections",
            value="connections",
            description="Allow /panel to list linked third-party accounts.",
            default=True,
        ),
        discord.SelectOption(
            label="Join Guilds",
            value="guilds.join",
            description="Allow adding the linked account to servers. Discord sends them a DM.",
        ),
        discord.SelectOption(
            label="Relationships",
            value="relationships.read",
            description="Allow /panel to list linked relationships.",
            default=True,
        ),
        discord.SelectOption(
            label="App Builds",
            value="applications.builds.read",
            description="Read build data for the linked account applications.",
        ),
        discord.SelectOption(
            label="Group DM Join",
            value="gdm.join",
            description="Allow adding the linked account to managed group DMs.",
        ),
        discord.SelectOption(
            label="Messages Read",
            value="messages.read",
            description="Read messages available to this app authorization.",
        ),
        discord.SelectOption(
            label="Incoming Webhook",
            value="webhook.incoming",
            description="Create an incoming webhook during authorization.",
        ),
    ]


def format_scope_list(scopes: list[str]) -> str:
    labels = [SCOPE_LABELS.get(scope, scope) for scope in scopes]
    return ", ".join(labels) if labels else "Identify"


def account_switcher_container(panel: PanelView) -> discord.ui.Container:
    children: list[discord.ui.Item] = [
        discord.ui.TextDisplay(account_switcher_text(panel.accounts, panel.page))
    ]

    if len(panel.accounts) >= 5:
        children.extend(
            [
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(AccountSelect(panel)),
            ]
        )
    elif len(panel.accounts) > 1:
        children.extend(
            [
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(
                    *[
                        AccountSwitchButton(panel, account, index)
                        for index, account in enumerate(panel.accounts)
                    ]
                ),
            ]
        )

    return discord.ui.Container(
        *children,
        accent_color=ACCENT_DEFAULT if panel.accounts else ACCENT_MUTED,
    )


def account_switcher_text(accounts: list[OAuthAccount], page: int) -> str:
    lines = [
        "## Saved Accounts",
        f"**Accounts:** `{len(accounts)} / {MAX_ACCOUNTS_PER_OWNER}`",
    ]
    if accounts:
        account = accounts[panel_page_index(accounts, page)]
        lines.append(
            f"**Viewing:** {safe_discord_text(account.display_name)} "
            f"(`{account.discord_user_id}`)"
        )
    return "\n".join(lines)


def account_switch_label(account: OAuthAccount, page: int) -> str:
    return truncate_label(f"{page + 1}. {account.display_name}", 80)


def account_select_label(account: OAuthAccount) -> str:
    return truncate_label(account.username or account.display_name, 100)


def account_select_description(account: OAuthAccount, page: int) -> str:
    return truncate_label(f"Saved account {page + 1} - ID {account.discord_user_id}", 100)


def account_select_value(account: OAuthAccount, page: int) -> str:
    if account.account_id is not None:
        return f"id:{account.account_id}"
    return f"page:{page}"


def panel_page_for_value(
    accounts: list[OAuthAccount],
    value: str,
    fallback: int = 0,
) -> int:
    if value.startswith("id:"):
        try:
            account_id = int(value.removeprefix("id:"))
        except ValueError:
            return panel_page_index(accounts, fallback)
        return panel_page_for_account(accounts, account_id, fallback)

    if value.startswith("page:"):
        try:
            return panel_page_index(accounts, int(value.removeprefix("page:")))
        except ValueError:
            return panel_page_index(accounts, fallback)

    return panel_page_index(accounts, fallback)


def truncate_label(value: str, max_length: int) -> str:
    text = str(value).strip() or "Unknown"
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 3]}..."


def panel_page_index(accounts: list[OAuthAccount], page: int) -> int:
    if not accounts:
        return 0
    return max(0, min(page, len(accounts) - 1))


def panel_page_for_account(
    accounts: list[OAuthAccount],
    account_id: int | None,
    fallback: int = 0,
) -> int:
    for index, account in enumerate(accounts):
        if account.account_id == account_id:
            return index
    return panel_page_index(accounts, fallback)


def panel_text(
    account: OAuthAccount | None,
    note: str | None = None,
    expires_at: int | None = None,
    timeout_seconds: int | None = None,
) -> str:
    timeout_lines = panel_timeout_lines(expires_at, timeout_seconds)
    if account is None:
        lines = [
            "## AuthSec Panel",
            "No OAuth account is linked yet. Run `/setup` to create an authorization link. "
            f"You can store up to {MAX_ACCOUNTS_PER_OWNER} accounts.",
        ]
        lines.extend(timeout_lines)
        if note:
            lines.extend(["", f"**Note:** {note}"])
        return "\n".join(lines)

    lines = [
        "## AuthSec Panel",
        "Manage the OAuth account linked to your Discord user. Unavailable actions "
        "stay disabled until the matching access is authorized.",
        "",
        *timeout_lines,
        "",
        f"**Linked account:** {account.display_name} (`{account.discord_user_id}`)",
        f"**MFA enabled:** {format_optional_bool(account.mfa_enabled)}",
        f"**IP Address:** `{account.ip_address or 'unknown'}`",
        f"**User Agent:** {format_user_agent(account.user_agent)}",
        f"**Access:** {format_scope_list(account.scopes)}",
        f"**Token expires:** <t:{account.expires_at}:R>",
        f"**Last updated:** <t:{account.updated_at}:R>",
    ]
    if account.has_scope("webhook.incoming"):
        lines.append(f"**OAuth webhook:** {webhook_status_text(account)}")
    if note:
        lines.extend(["", f"**Note:** {note}"])
    return "\n".join(lines)


def password_text_input(label: str) -> discord.ui.TextInput:
    return discord.ui.TextInput(
        label=label,
        style=discord.TextStyle.short,
        min_length=PASSWORD_MIN_LENGTH,
        max_length=PASSWORD_MAX_LENGTH,
    )


def encryption_unlock_notice() -> discord.ui.TextDisplay:
    return discord.ui.TextDisplay(
        "This password will be used to unlock encrypted data once."
    )


def panel_timeout_lines(
    expires_at: int | None,
    timeout_seconds: int | None,
) -> list[str]:
    if expires_at is None or timeout_seconds is None:
        return []

    if int(time.time()) >= int(expires_at):
        countdown = "Expired"
    else:
        countdown = f"<t:{int(expires_at)}:R>"

    return [
        f"**Panel buttons disable:** {countdown} (<t:{int(expires_at)}:T>)",
    ]


def encryption_settings_text(
    oauth_client: DiscordOAuthClient,
    owner_id: int,
    settings: OwnerSecuritySettings,
    note: str | None = None,
) -> str:
    enabled = oauth_client.is_encryption_enabled(owner_id)
    status = "Enabled" if enabled else "Disabled"

    lines = [
        "## Encryption",
        f"**Status:** {status}",
        "**Encryption method:** AES-GCM for saved sensitive fields",
        "**Password check:** SHA-256 hash",
        f"**Panel buttons disable after:** {format_timeout_label(settings.panel_timeout_seconds)}",
        "",
        "When enabled, `/panel` asks for the password every time it is opened. "
        "The opened panel stays clickable only for the timeout above.",
        "",
        "Saved access tokens, refresh tokens, IP addresses, user agents, and "
        "webhook tokens are encrypted with the raw password.",
        f"Passwords must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters.",
    ]
    if note:
        lines.extend(["", f"**Note:** {note}"])
    return "\n".join(lines)


def format_timeout_label(seconds: int) -> str:
    minutes = max(1, int(seconds) // 60)
    suffix = "minute" if minutes == 1 else "minutes"
    return f"{minutes} {suffix}"


def format_oauth_link_ttl_label(seconds: int) -> str:
    seconds = int(seconds)
    if seconds < 60 * 60:
        minutes = max(1, seconds // 60)
        return f"{minutes} minutes"
    hours = seconds // (60 * 60)
    suffix = "hour" if hours == 1 else "hours"
    return f"{hours} {suffix}"


def format_oauth_link_use_label(use_limit: int | None) -> str:
    if use_limit in (None, 0):
        return "Unlimited uses until expiry"
    use_limit = int(use_limit)
    suffix = "use" if use_limit == 1 else "uses"
    return f"{use_limit} {suffix}"


def build_user_view(
    user: dict[str, Any],
    account: OAuthAccount | None = None,
    oauth_client: DiscordOAuthClient | None = None,
    owner_id: int | None = None,
) -> discord.ui.LayoutView:
    lines = [
        f"**ID:** `{user.get('id', 'unknown')}`",
        f"**Username:** {user.get('username', 'unknown')}",
        f"**Display name:** {user.get('global_name') or 'none'}",
    ]
    if account is not None:
        lines.append(f"**IP Address:** `{account.ip_address or 'unknown'}`")
        lines.append(f"**User Agent:** {format_user_agent(account.user_agent)}")
    if "email" in user:
        lines.append(f"**Email:** {user.get('email') or 'none'}")
    if "verified" in user:
        lines.append(f"**Verified:** {format_optional_bool(user.get('verified'))}")
    if "mfa_enabled" in user:
        lines.append(f"**MFA enabled:** {format_optional_bool(user.get('mfa_enabled'))}")

    body = "\n".join(lines)
    children: list[discord.ui.Item] = [
        discord.ui.TextDisplay(f"## Linked Account Details\n{body}")
    ]
    if account is not None and oauth_client is not None:
        children.extend(
            [
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(
                    IPInfoButton(oauth_client, owner_id, account.ip_address)
                ),
            ]
        )

    view = discord.ui.LayoutView(timeout=300)
    view.add_item(
        discord.ui.Container(
            *children,
            accent_color=ACCENT_DEFAULT,
        )
    )
    return view


def build_ip_info_view(payload: dict[str, Any]) -> discord.ui.LayoutView:
    connection = dict_payload(payload.get("connection"))
    security = dict_payload(payload.get("security"))

    lines = [
        f"**Location:** {format_compact_location(payload)}",
        f"**ISP:** {format_unknown(connection.get('isp'))}",
        f"**VPN Status:** {format_vpn_status(security)}",
    ]

    body = "\n".join(lines)
    view = discord.ui.LayoutView(timeout=300)
    view.add_item(
        discord.ui.Container(
            discord.ui.TextDisplay(f"## IP Info\n{body}"),
            accent_color=ACCENT_DEFAULT,
        )
    )
    return view


def build_list_view(
    title: str,
    items: list[dict[str, Any]],
    item_name: str,
) -> discord.ui.LayoutView:
    if not items:
        return TextContainerView(
            title,
            f"No {item_name}s were returned.",
            ACCENT_MUTED,
        )

    lines = []
    for item in items[:10]:
        user = item.get("user") if isinstance(item.get("user"), dict) else {}
        name = (
            item.get("name")
            or item.get("username")
            or user.get("global_name")
            or user.get("username")
            or item.get("id")
            or user.get("id")
            or "Unknown"
        )
        item_id = item.get("id") or user.get("id")
        item_type = item.get("type")
        suffix = f" ({item_type})" if item_type else ""
        lines.append(f"- {name}{suffix}" + (f" - `{item_id}`" if item_id else ""))

    if len(items) > 10:
        lines.append("")
        lines.append(f"Showing 10 of {len(items)} returned {item_name}s.")

    return TextContainerView(title, "\n".join(lines), ACCENT_DEFAULT)


def guild_section(
    guild: dict[str, Any],
    member_detail: dict[str, Any] | None = None,
) -> discord.ui.Section:
    return discord.ui.Section(
        guild_text(guild, member_detail),
        accessory=discord.ui.Thumbnail(guild_icon_url(guild)),
    )


def guild_text(
    guild: dict[str, Any],
    member_detail: dict[str, Any] | None = None,
) -> str:
    permissions = guild_permissions(guild)
    lines = [
        f"### {guild.get('name') or 'Unknown server'}",
        f"**ID:** `{guild.get('id', 'unknown')}`",
        f"**Owner:** {format_optional_bool(guild.get('owner'))}",
        f"**Permissions:** {permissions}",
    ]

    vanity_invite = guild_vanity_invite(guild)
    if vanity_invite:
        lines.append(f"**Vanity invite:** {vanity_invite}")

    joined_at = (member_detail or {}).get("joined_at")
    if joined_at:
        lines.append(f"**Joined:** {format_time_value(joined_at)}")

    approximate_members = guild.get("approximate_member_count")
    approximate_presence = guild.get("approximate_presence_count")
    if approximate_members is not None:
        lines.append(f"**Approx. members:** {approximate_members}")
    if approximate_presence is not None:
        lines.append(f"**Approx. online:** {approximate_presence}")

    return "\n".join(lines)


def guild_icon_url(guild: dict[str, Any]) -> str:
    guild_id = guild.get("id")
    icon_hash = guild.get("icon")
    if guild_id and icon_hash:
        extension = "gif" if str(icon_hash).startswith("a_") else "webp"
        return f"https://cdn.discordapp.com/icons/{guild_id}/{icon_hash}.{extension}?size=128"

    return "https://cdn.discordapp.com/embed/avatars/0.png"


def guild_permissions(guild: dict[str, Any]) -> str:
    raw_permissions = guild.get("permissions")
    if raw_permissions is None:
        return "Unknown"

    try:
        permissions = discord.Permissions(int(raw_permissions))
    except (TypeError, ValueError):
        return "Unknown"

    if permissions.administrator:
        return "Administrator"

    labels = [format_permission_name(name) for name, enabled in permissions if enabled]
    if labels:
        return ", ".join(labels)
    return "None"


def guild_vanity_invite(guild: dict[str, Any]) -> str | None:
    value = (
        guild.get("vanity_url_code")
        or guild.get("vanity_invite")
        or guild.get("vanity_url")
    )
    if not value:
        return None

    value = str(value)
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return f"https://discord.gg/{value}"


def format_permission_name(name: str) -> str:
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


def bot_has_admin_in_interaction(interaction: discord.Interaction) -> bool:
    if interaction.guild is None:
        return False

    app_permissions = getattr(interaction, "app_permissions", None)
    if app_permissions is not None and app_permissions.administrator:
        return True

    guild_me = getattr(interaction.guild, "me", None)
    if guild_me is not None and guild_me.guild_permissions.administrator:
        return True

    client_user = getattr(getattr(interaction, "client", None), "user", None)
    if client_user is None:
        return False

    guild_member = interaction.guild.get_member(client_user.id)
    if guild_member is None:
        return False

    return guild_member.guild_permissions.administrator


def can_show_guild_join_dates(account: OAuthAccount | None) -> bool:
    return bool(account and account.has_scope("guilds.members.read"))


async def fetch_guild_page_member_details(
    oauth_client: DiscordOAuthClient,
    owner_id: int,
    guilds: list[dict[str, Any]],
    page: int,
    account: OAuthAccount | None = None,
    account_id: int | None = None,
) -> dict[str, dict[str, Any]]:
    if account is not None and not can_show_guild_join_dates(account):
        return {}

    start = max(0, page) * GuildsPageView.page_size
    guild_ids = [
        str(guild.get("id"))
        for guild in guilds[start : start + GuildsPageView.page_size]
        if guild.get("id")
    ]
    if not guild_ids:
        return {}

    try:
        return await asyncio.to_thread(
            oauth_client.fetch_guild_member_details,
            owner_id,
            guild_ids,
            account_id,
        )
    except DiscordApiError:
        return {}


def relationship_section(relationship: dict[str, Any]) -> discord.ui.Section:
    return discord.ui.Section(
        relationship_text(relationship),
        accessory=discord.ui.Thumbnail(relationship_avatar_url(relationship)),
    )


def relationship_text(relationship: dict[str, Any]) -> str:
    user = relationship_user(relationship)
    name = relationship_display_name(relationship)
    user_id = relationship_user_id(relationship)
    username = user.get("username") or relationship.get("username")
    relationship_type = relationship_type_label(relationship)

    lines = [
        f"### {name}",
        f"**User ID:** `{user_id or 'unknown'}`",
        f"**Relationship:** {relationship_type}",
    ]

    if username and username != name:
        lines.append(f"**Username:** {username}")

    nickname = relationship.get("nickname") or relationship.get("nick")
    if nickname:
        lines.append(f"**Nickname:** {nickname}")

    since = (
        relationship.get("since")
        or relationship.get("created_at")
        or relationship.get("createdAt")
        or relationship.get("updated_at")
        or relationship.get("updatedAt")
    )
    if since:
        lines.append(f"**Since:** {format_time_value(since)}")

    return "\n".join(lines)


def relationship_user(relationship: dict[str, Any]) -> dict[str, Any]:
    for key in ("user", "discord_user", "discordUser", "recipient"):
        value = relationship.get(key)
        if isinstance(value, dict):
            return value
    return {}


def relationship_display_name(relationship: dict[str, Any]) -> str:
    user = relationship_user(relationship)
    return str(
        user.get("global_name")
        or user.get("display_name")
        or user.get("username")
        or relationship.get("global_name")
        or relationship.get("display_name")
        or relationship.get("username")
        or relationship_user_id(relationship)
        or "Unknown user"
    )


def relationship_user_id(relationship: dict[str, Any]) -> str | None:
    user = relationship_user(relationship)
    value = (
        user.get("id")
        or relationship.get("user_id")
        or relationship.get("userId")
        or relationship.get("id")
    )
    if value is None:
        return None
    return str(value)


def relationship_avatar_url(relationship: dict[str, Any]) -> str:
    user = relationship_user(relationship)
    user_id = relationship_user_id(relationship)
    avatar_hash = user.get("avatar") or relationship.get("avatar")
    if user_id and avatar_hash:
        extension = "gif" if str(avatar_hash).startswith("a_") else "webp"
        return f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.{extension}?size=128"

    return "https://cdn.discordapp.com/embed/avatars/0.png"


def relationship_type_label(relationship: dict[str, Any]) -> str:
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
        normalized = value.strip()
        if normalized.isdigit():
            value = int(normalized)
        else:
            return normalized.replace("_", " ").replace("-", " ").title()

    labels = {
        0: "None",
        1: "Friend",
        2: "Blocked",
        3: "Incoming Request",
        4: "Outgoing Request",
        5: "Implicit",
    }
    return labels.get(value, str(value))


def webhook_status_text(account: OAuthAccount) -> str:
    if not account.has_webhook:
        return "Not stored"

    parts = ["Stored"]
    if account.webhook_name:
        parts.append(safe_discord_text(account.webhook_name))
    if account.webhook_channel_id:
        parts.append(f"channel `{account.webhook_channel_id}`")
    if account.webhook_guild_id:
        parts.append(f"guild `{account.webhook_guild_id}`")
    return " - ".join(parts)


def format_user_agent(value: str | None) -> str:
    if not value:
        return "`unknown`"
    text = discord.utils.escape_markdown(
        safe_discord_text(truncate_label(value, 300))
    )
    return f"`{text}`"


def safe_optional_text(value: Any, max_length: int = 120) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return discord.utils.escape_markdown(safe_discord_text(truncate_label(text, max_length)))


def format_unknown(value: Any, max_length: int = 120) -> str:
    return safe_optional_text(value, max_length) or "Unknown"


def format_name_with_code(name_value: Any, code_value: Any) -> str:
    name = safe_optional_text(name_value)
    code = safe_optional_text(code_value, 16)
    if name and code:
        return f"{name} (`{code}`)"
    if name:
        return name
    if code:
        return f"`{code}`"
    return "Unknown"


def format_compact_location(payload: dict[str, Any]) -> str:
    parts = [
        safe_optional_text(payload.get("city")),
        safe_optional_text(payload.get("region_name")),
        safe_optional_text(payload.get("country_name")),
    ]
    location = ", ".join(part for part in parts if part)
    country_code = safe_optional_text(payload.get("country_code"), 16)
    if location and country_code:
        return f"{location} (`{country_code}`)"
    if location:
        return location
    if country_code:
        return f"`{country_code}`"
    return "Unknown"


def format_vpn_status(security: dict[str, Any]) -> str:
    if not security:
        return "Unknown"

    vpn_service = safe_optional_text(security.get("vpn_service"))
    if vpn_service:
        return f"Detected ({vpn_service})"
    if security.get("is_proxy") is True or security.get("is_tor") is True:
        return "Possible anonymizer"
    return "Not detected"


def dict_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def safe_discord_text(value: Any) -> str:
    return discord.utils.escape_mentions(str(value))


def format_time_value(value: Any) -> str:
    timestamp = value_timestamp(value)
    if timestamp is None:
        return str(value)
    return f"<t:{timestamp}:F> (<t:{timestamp}:R>)"


def value_timestamp(value: Any) -> int | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        return int(value)
    elif isinstance(value, str):
        parsed = parse_datetime_string(value)
        if parsed is None:
            return None
    else:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def parse_datetime_string(value: str) -> datetime | None:
    text = value.strip()
    if not text:
        return None

    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"

    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def build_faq_view() -> discord.ui.LayoutView:
    return TextContainerView(
        "AuthSec FAQ",
        "\n".join(
            [
                "**What does `/setup` do?**",
                "It creates a short-lived Discord OAuth link with the scopes you select.",
                "",
                "**Where is data stored?**",
                "Linked account tokens, MFA status when Discord returns it, and callback IP metadata are stored in SQLite.",
                "",
                "**Can I disconnect?**",
                "Yes. `/panel` has a Disconnect button that revokes the token with Discord and removes the local record.",
                "",
                "**Why do some buttons disable?**",
                "Panel buttons are enabled only when the linked account granted the matching scope.",
            ]
        ),
        ACCENT_DEFAULT,
    )


def build_ping_view(latency_ms: int) -> discord.ui.LayoutView:
    return TextContainerView(
        "Pong",
        f"Gateway latency: `{latency_ms}ms`.",
        ACCENT_SUCCESS,
    )


def build_error_view(message: str) -> discord.ui.LayoutView:
    return TextContainerView("Something went wrong", message, ACCENT_ERROR)


def build_blocked_view() -> discord.ui.LayoutView:
    return TextContainerView(
        "Access blocked",
        "You can't use this bot.",
        ACCENT_ERROR,
    )


def build_linked_dm_view(
    account: OAuthAccount,
    encryption_enabled: bool = True,
) -> discord.ui.LayoutView:
    lines = [
        "Use `/panel` to view, refresh, or disconnect this account.",
    ]
    if not encryption_enabled:
        lines.extend(
            [
                "",
                "**Warning:** Encryption is disabled. This account's access token, "
                "refresh token, IP address, user agent, and webhook token are stored "
                "unencrypted. Run `/encryption` to enable encryption.",
            ]
        )
    lines.extend(
        [
            "",
            f"**Linked account:** {account.display_name} (`{account.discord_user_id}`)",
            f"**MFA enabled:** {format_optional_bool(account.mfa_enabled)}",
            f"**IP Address:** `{account.ip_address or 'unknown'}`",
            f"**User Agent:** {format_user_agent(account.user_agent)}",
            f"**Access:** {format_scope_list(account.scopes)}",
            f"**Linked:** <t:{int(time.time())}:R>",
        ]
    )
    return TextContainerView(
        "OAuth account linked",
        "\n".join(lines),
        ACCENT_SUCCESS,
    )


def parse_color(value: str | None) -> discord.Color:
    if not value:
        return ACCENT_DEFAULT

    text = value.strip().lower()
    if text in COLOR_NAMES:
        return COLOR_NAMES[text]

    if text.startswith("#"):
        text = text[1:]

    try:
        return discord.Color(int(text, 16))
    except ValueError:
        return ACCENT_DEFAULT


def format_optional_bool(value: Any) -> str:
    if value is None:
        return "Unknown"
    return "Yes" if bool(value) else "No"


def _is_discord_oauth_url(url: str) -> bool:
    parsed = urlparse(url)
    return (
        parsed.scheme == "https"
        and parsed.netloc in {"discord.com", "www.discord.com"}
        and parsed.path.startswith("/oauth2/authorize")
    )
