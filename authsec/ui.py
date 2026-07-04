from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import urlparse

import discord

from .models import OAuthAccount
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


class SetupScopeView(discord.ui.LayoutView):
    def __init__(self, oauth_client: DiscordOAuthClient, owner_id: int):
        super().__init__(timeout=300)
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.selected_scopes = ["email", "guilds"]
        self.add_item(
            discord.ui.Container(
                discord.ui.TextDisplay(
                    "## Set up OAuth\n"
                    "Choose the scopes you want to request. The `identify` scope "
                    "is always included because it is needed to know which Discord "
                    "account authorized the app."
                ),
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(ScopeSelect(self)),
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
        super().__init__(
            placeholder="Choose optional OAuth scopes",
            min_values=0,
            max_values=5,
            options=oauth_scope_options(),
        )
        self.parent_view = parent

    async def callback(self, interaction: discord.Interaction):
        self.parent_view.selected_scopes = list(self.values)
        await interaction.response.defer()


class GenerateLinkButton(discord.ui.Button):
    def __init__(self, parent: SetupScopeView):
        super().__init__(
            label="Generate OAuth Link",
            style=discord.ButtonStyle.primary,
        )
        self.parent_view = parent

    async def callback(self, interaction: discord.Interaction):
        url = await asyncio.to_thread(
            self.parent_view.oauth_client.build_authorization_url,
            self.parent_view.owner_id,
            self.parent_view.selected_scopes,
        )
        scopes = [*self.parent_view.selected_scopes, "identify"]
        await interaction.response.send_message(
            view=GeneratedOAuthLinkView(url, scopes),
            ephemeral=True,
        )


class GeneratedOAuthLinkView(discord.ui.LayoutView):
    def __init__(self, url: str, scopes: list[str]):
        super().__init__(timeout=None)
        self.add_item(
            discord.ui.Container(
                discord.ui.TextDisplay(
                    "## OAuth link created\n"
                    "Open this link to authorize the selected scopes. The link "
                    "expires in a few minutes and can only be used once.\n\n"
                    f"**Scopes:** {', '.join(scopes)}"
                ),
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(
                    discord.ui.Button(
                        label="Authorize",
                        style=discord.ButtonStyle.link,
                        url=url,
                    )
                ),
                accent_color=ACCENT_SUCCESS,
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


class PanelView(discord.ui.LayoutView):
    def __init__(
        self,
        oauth_client: DiscordOAuthClient,
        owner_id: int,
        account: OAuthAccount | None,
        can_join_here: bool,
        note: str | None = None,
    ):
        super().__init__(timeout=300)
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.account = account
        has_account = account is not None

        self.add_item(
            discord.ui.Container(
                discord.ui.TextDisplay(panel_text(account, note)),
                discord.ui.Separator(spacing=discord.SeparatorSpacing.small),
                discord.ui.ActionRow(
                    RefreshButton(self, disabled=not has_account),
                    DetailsButton(self, disabled=not has_account),
                    GuildsButton(
                        self,
                        disabled=not has_account or not account.has_scope("guilds"),
                    ),
                    ConnectionsButton(
                        self,
                        disabled=not has_account or not account.has_scope("connections"),
                    ),
                ),
                discord.ui.ActionRow(
                    RelationshipsButton(
                        self,
                        disabled=not has_account
                        or not account.has_scope("relationships.read"),
                    ),
                    JoinServerButton(
                        self,
                        disabled=(
                            not has_account
                            or not account.has_scope("guilds.join")
                            or not can_join_here
                        ),
                    ),
                    DisconnectButton(self, disabled=not has_account),
                ),
                accent_color=ACCENT_DEFAULT if has_account else ACCENT_MUTED,
            )
        )

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.owner_id:
            return True

        await interaction.response.send_message(
            view=build_error_view("This panel belongs to someone else."),
            ephemeral=True,
        )
        return False


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
        try:
            account = await asyncio.to_thread(
                self.panel.oauth_client.refresh_account,
                self.panel.owner_id,
                True,
            )
            note = "Token refreshed. Account metadata was updated from Discord."
        except DiscordApiError as exc:
            account = await asyncio.to_thread(
                self.panel.oauth_client.get_account,
                self.panel.owner_id,
                False,
            )
            note = str(exc)

        await interaction.edit_original_response(
            view=PanelView(
                self.panel.oauth_client,
                self.panel.owner_id,
                account,
                can_join_here=interaction.guild is not None,
                note=note,
            )
        )


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
            )
            view = build_user_view(user)
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
            )
            view = build_list_view("Linked Account Guilds", guilds, "guild")
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
            )
            view = build_list_view(
                "Linked Relationships",
                relationships,
                "relationship",
            )
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        await interaction.followup.send(view=view, ephemeral=True)


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

        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            message = await asyncio.to_thread(
                self.panel.oauth_client.add_to_guild,
                self.panel.owner_id,
                interaction.guild.id,
            )
            view = TextContainerView("Join complete", message, ACCENT_SUCCESS)
        except DiscordApiError as exc:
            view = build_error_view(str(exc))

        await interaction.followup.send(view=view, ephemeral=True)


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
        revoked = await asyncio.to_thread(
            self.panel.oauth_client.disconnect_account,
            self.panel.owner_id,
        )
        note = "Disconnected and revoked with Discord." if revoked else "Disconnected locally."
        await interaction.edit_original_response(
            view=PanelView(
                self.panel.oauth_client,
                self.panel.owner_id,
                None,
                can_join_here=interaction.guild is not None,
                note=note,
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
            label="Connections",
            value="connections",
            description="Allow /panel to list linked third-party accounts.",
        ),
        discord.SelectOption(
            label="Join Guilds",
            value="guilds.join",
            description="Allow adding the linked account to this server.",
        ),
        discord.SelectOption(
            label="Relationships",
            value="relationships.read",
            description="Requires Discord approval before it works.",
        ),
    ]


def panel_text(account: OAuthAccount | None, note: str | None = None) -> str:
    if account is None:
        lines = [
            "## AuthSec Panel",
            "No OAuth account is linked yet. Run `/setup` to create an authorization link.",
        ]
        if note:
            lines.extend(["", f"**Note:** {note}"])
        return "\n".join(lines)

    lines = [
        "## AuthSec Panel",
        "Manage the OAuth account linked to your Discord user.",
        "",
        f"**Linked account:** {account.display_name} (`{account.discord_user_id}`)",
        f"**MFA enabled:** {format_optional_bool(account.mfa_enabled)}",
        f"**Authorization IP:** `{account.ip_address or 'unknown'}`",
        f"**Scopes:** {', '.join(account.scopes) or 'identify'}",
        f"**Token expires:** <t:{account.expires_at}:R>",
        f"**Last updated:** <t:{account.updated_at}:R>",
    ]
    if note:
        lines.extend(["", f"**Note:** {note}"])
    return "\n".join(lines)


def build_user_view(user: dict[str, Any]) -> discord.ui.LayoutView:
    lines = [
        f"**ID:** `{user.get('id', 'unknown')}`",
        f"**Username:** {user.get('username', 'unknown')}",
        f"**Display name:** {user.get('global_name') or 'none'}",
    ]
    if "email" in user:
        lines.append(f"**Email:** {user.get('email') or 'none'}")
    if "verified" in user:
        lines.append(f"**Verified:** {format_optional_bool(user.get('verified'))}")
    if "mfa_enabled" in user:
        lines.append(f"**MFA enabled:** {format_optional_bool(user.get('mfa_enabled'))}")

    return TextContainerView(
        "Linked Account Details",
        "\n".join(lines),
        ACCENT_DEFAULT,
    )


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


def build_linked_dm_view(account: OAuthAccount) -> discord.ui.LayoutView:
    return TextContainerView(
        "OAuth account linked",
        "\n".join(
            [
                "Use `/panel` to view, refresh, or disconnect this account.",
                "",
                f"**Linked account:** {account.display_name} (`{account.discord_user_id}`)",
                f"**MFA enabled:** {format_optional_bool(account.mfa_enabled)}",
                f"**Authorization IP:** `{account.ip_address or 'unknown'}`",
                f"**Scopes:** {', '.join(account.scopes)}",
                f"**Linked:** <t:{int(time.time())}:R>",
            ]
        ),
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
