from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import urlparse

import discord

from .models import OAuthAccount
from .oauth import DiscordApiError, DiscordOAuthClient


OPTIONAL_SCOPES = [
    discord.SelectOption(
        label="Email",
        value="email",
        description="Allow /panel to show the linked account email.",
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
        description="Discord approval is required before this scope works.",
    ),
]


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


class SetupScopeView(discord.ui.View):
    def __init__(self, oauth_client: DiscordOAuthClient, owner_id: int):
        super().__init__(timeout=300)
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.selected_scopes = ["email", "guilds"]
        self.add_item(ScopeSelect(self))
        self.add_item(GenerateLinkButton(self))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.owner_id:
            return True

        await interaction.response.send_message(
            "This setup menu belongs to someone else.",
            ephemeral=True,
        )
        return False


class ScopeSelect(discord.ui.Select):
    def __init__(self, parent: SetupScopeView):
        super().__init__(
            placeholder="Choose optional OAuth scopes",
            min_values=0,
            max_values=len(OPTIONAL_SCOPES),
            options=OPTIONAL_SCOPES,
            row=0,
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
            row=1,
        )
        self.parent_view = parent

    async def callback(self, interaction: discord.Interaction):
        url = await asyncio.to_thread(
            self.parent_view.oauth_client.build_authorization_url,
            self.parent_view.owner_id,
            self.parent_view.selected_scopes,
        )
        embed = discord.Embed(
            title="OAuth link created",
            description=(
                "Open this link to authorize the selected scopes. "
                "The link expires in a few minutes and can only be used once."
            ),
            color=discord.Color.blurple(),
        )
        embed.add_field(name="Scopes", value=", ".join(self.parent_view.selected_scopes + ["identify"]))
        await interaction.response.send_message(
            embed=embed,
            view=OAuthLinkView(url),
            ephemeral=True,
        )


class OAuthLinkView(discord.ui.View):
    def __init__(self, url: str):
        super().__init__(timeout=None)
        self.add_item(
            discord.ui.Button(
                label="Authorize",
                style=discord.ButtonStyle.link,
                url=url,
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
                "Please provide a Discord OAuth2 authorization URL.",
                ephemeral=True,
            )
            return

        embed = discord.Embed(
            title=self.title_input.value.strip(),
            description=self.description_input.value.strip(),
            color=parse_color(self.color_input.value),
        )
        await interaction.response.send_message(
            embed=embed,
            view=OAuthLinkView(link),
        )


class PanelView(discord.ui.View):
    def __init__(
        self,
        oauth_client: DiscordOAuthClient,
        owner_id: int,
        account: OAuthAccount | None,
        can_join_here: bool,
    ):
        super().__init__(timeout=300)
        self.oauth_client = oauth_client
        self.owner_id = int(owner_id)
        self.account = account
        has_account = account is not None

        self.add_item(RefreshButton(self, disabled=not has_account))
        self.add_item(DetailsButton(self, disabled=not has_account))
        self.add_item(
            GuildsButton(
                self,
                disabled=not has_account or not account.has_scope("guilds"),
            )
        )
        self.add_item(
            ConnectionsButton(
                self,
                disabled=not has_account or not account.has_scope("connections"),
            )
        )
        self.add_item(
            RelationshipsButton(
                self,
                disabled=not has_account or not account.has_scope("relationships.read"),
            )
        )
        self.add_item(
            JoinServerButton(
                self,
                disabled=(
                    not has_account
                    or not account.has_scope("guilds.join")
                    or not can_join_here
                ),
            )
        )
        self.add_item(DisconnectButton(self, disabled=not has_account))

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.owner_id:
            return True

        await interaction.response.send_message(
            "This panel belongs to someone else.",
            ephemeral=True,
        )
        return False


class RefreshButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Refresh",
            style=discord.ButtonStyle.primary,
            disabled=disabled,
            row=0,
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
            error = None
        except DiscordApiError as exc:
            account = await asyncio.to_thread(
                self.panel.oauth_client.get_account,
                self.panel.owner_id,
                False,
            )
            error = str(exc)

        await interaction.edit_original_response(
            embed=build_panel_embed(account, error),
            view=PanelView(
                self.panel.oauth_client,
                self.panel.owner_id,
                account,
                can_join_here=interaction.guild is not None,
            ),
        )


class DetailsButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Details",
            style=discord.ButtonStyle.secondary,
            disabled=disabled,
            row=0,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            user = await asyncio.to_thread(
                self.panel.oauth_client.fetch_current_user,
                self.panel.owner_id,
            )
            embed = build_user_embed(user)
        except DiscordApiError as exc:
            embed = build_error_embed(str(exc))

        await interaction.followup.send(embed=embed, ephemeral=True)


class GuildsButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Guilds",
            style=discord.ButtonStyle.secondary,
            disabled=disabled,
            row=0,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            guilds = await asyncio.to_thread(
                self.panel.oauth_client.fetch_guilds,
                self.panel.owner_id,
            )
            embed = build_list_embed("Linked Account Guilds", guilds, "guild")
        except DiscordApiError as exc:
            embed = build_error_embed(str(exc))

        await interaction.followup.send(embed=embed, ephemeral=True)


class ConnectionsButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Connections",
            style=discord.ButtonStyle.secondary,
            disabled=disabled,
            row=0,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            connections = await asyncio.to_thread(
                self.panel.oauth_client.fetch_connections,
                self.panel.owner_id,
            )
            embed = build_list_embed("Linked Connections", connections, "connection")
        except DiscordApiError as exc:
            embed = build_error_embed(str(exc))

        await interaction.followup.send(embed=embed, ephemeral=True)


class RelationshipsButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Relationships",
            style=discord.ButtonStyle.secondary,
            disabled=disabled,
            row=1,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        try:
            relationships = await asyncio.to_thread(
                self.panel.oauth_client.fetch_relationships,
                self.panel.owner_id,
            )
            embed = build_list_embed(
                "Linked Relationships",
                relationships,
                "relationship",
            )
        except DiscordApiError as exc:
            embed = build_error_embed(str(exc))

        await interaction.followup.send(embed=embed, ephemeral=True)


class JoinServerButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Join Server",
            style=discord.ButtonStyle.success,
            disabled=disabled,
            row=1,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        if interaction.guild is None:
            await interaction.response.send_message(
                "Run this from a server to use guild joining.",
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
            embed = discord.Embed(title="Join complete", description=message, color=discord.Color.green())
        except DiscordApiError as exc:
            embed = build_error_embed(str(exc))

        await interaction.followup.send(embed=embed, ephemeral=True)


class DisconnectButton(discord.ui.Button):
    def __init__(self, panel: PanelView, disabled: bool):
        super().__init__(
            label="Disconnect",
            style=discord.ButtonStyle.danger,
            disabled=disabled,
            row=1,
        )
        self.panel = panel

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer()
        revoked = await asyncio.to_thread(
            self.panel.oauth_client.disconnect_account,
            self.panel.owner_id,
        )
        message = "Disconnected and revoked with Discord." if revoked else "Disconnected locally."
        await interaction.edit_original_response(
            embed=build_panel_embed(None, message),
            view=PanelView(
                self.panel.oauth_client,
                self.panel.owner_id,
                None,
                can_join_here=interaction.guild is not None,
            ),
        )


def build_setup_embed() -> discord.Embed:
    embed = discord.Embed(
        title="Set up OAuth",
        description=(
            "Choose the scopes you want to request. The identify scope is always included "
            "because it is needed to know which Discord account was authorized."
        ),
        color=discord.Color.blurple(),
    )
    embed.add_field(
        name="Tip",
        value="Only request scopes you actually need. Smaller scope lists are easier for users to trust.",
        inline=False,
    )
    return embed


def build_panel_embed(account: OAuthAccount | None, note: str | None = None) -> discord.Embed:
    if account is None:
        embed = discord.Embed(
            title="AuthSec Panel",
            description="No OAuth account is linked yet. Run /setup to create an authorization link.",
            color=discord.Color.dark_theme(),
        )
        if note:
            embed.add_field(name="Note", value=note, inline=False)
        return embed

    embed = discord.Embed(
        title="AuthSec Panel",
        description="Manage the OAuth account linked to your Discord user.",
        color=discord.Color.blurple(),
    )
    embed.add_field(name="Linked account", value=f"{account.display_name}\n`{account.discord_user_id}`", inline=False)
    embed.add_field(name="Scopes", value=", ".join(account.scopes) or "identify", inline=False)
    embed.add_field(name="Token expires", value=f"<t:{account.expires_at}:R>", inline=True)
    embed.add_field(name="Last updated", value=f"<t:{account.updated_at}:R>", inline=True)
    if note:
        embed.add_field(name="Note", value=note, inline=False)
    return embed


def build_user_embed(user: dict[str, Any]) -> discord.Embed:
    embed = discord.Embed(
        title="Linked Account Details",
        color=discord.Color.blurple(),
    )
    embed.add_field(name="ID", value=str(user.get("id", "Unknown")), inline=False)
    embed.add_field(name="Username", value=str(user.get("username", "Unknown")), inline=True)
    embed.add_field(name="Display name", value=str(user.get("global_name") or "None"), inline=True)
    if "email" in user:
        embed.add_field(name="Email", value=str(user.get("email") or "None"), inline=False)
    if "verified" in user:
        embed.add_field(name="Verified", value=str(user.get("verified")), inline=True)
    return embed


def build_list_embed(title: str, items: list[dict[str, Any]], item_name: str) -> discord.Embed:
    embed = discord.Embed(title=title, color=discord.Color.blurple())
    if not items:
        embed.description = f"No {item_name}s were returned."
        return embed

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

    embed.description = "\n".join(lines)
    if len(items) > 10:
        embed.set_footer(text=f"Showing 10 of {len(items)} returned {item_name}s.")
    return embed


def build_faq_embed() -> discord.Embed:
    embed = discord.Embed(
        title="AuthSec FAQ",
        description="How this bot handles Discord OAuth authorization.",
        color=discord.Color.blurple(),
    )
    embed.add_field(
        name="What does /setup do?",
        value="It creates a short-lived Discord OAuth link with the scopes you select.",
        inline=False,
    )
    embed.add_field(
        name="Where is data stored?",
        value="Linked account tokens and metadata are stored in the local SQLite database.",
        inline=False,
    )
    embed.add_field(
        name="Can I disconnect?",
        value="Yes. /panel has a Disconnect button that revokes the token with Discord and removes the local record.",
        inline=False,
    )
    embed.add_field(
        name="Why do some buttons disable?",
        value="Panel buttons are enabled only when the linked account granted the matching scope.",
        inline=False,
    )
    return embed


def build_error_embed(message: str) -> discord.Embed:
    return discord.Embed(
        title="Something went wrong",
        description=message,
        color=discord.Color.red(),
    )


def build_linked_dm_embed(account: OAuthAccount) -> discord.Embed:
    embed = discord.Embed(
        title="OAuth account linked",
        description="Use /panel to view, refresh, or disconnect this account.",
        color=discord.Color.green(),
    )
    embed.add_field(name="Linked account", value=f"{account.display_name}\n`{account.discord_user_id}`", inline=False)
    embed.add_field(name="Scopes", value=", ".join(account.scopes), inline=False)
    embed.add_field(name="Linked", value=f"<t:{int(time.time())}:R>", inline=True)
    return embed


def parse_color(value: str | None) -> discord.Color:
    if not value:
        return discord.Color.blurple()

    text = value.strip().lower()
    if text in COLOR_NAMES:
        return COLOR_NAMES[text]

    if text.startswith("#"):
        text = text[1:]

    try:
        return discord.Color(int(text, 16))
    except ValueError:
        return discord.Color.blurple()


def _is_discord_oauth_url(url: str) -> bool:
    parsed = urlparse(url)
    return (
        parsed.scheme == "https"
        and parsed.netloc in {"discord.com", "www.discord.com"}
        and parsed.path.startswith("/oauth2/authorize")
    )
