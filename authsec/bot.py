from __future__ import annotations

import asyncio
import logging

import discord
from discord import app_commands

from .models import OAuthAccount
from .oauth import DiscordApiError, DiscordOAuthClient
from .settings import Settings
from .ui import (
    AccessRequiredView,
    CreateOAuthButtonModal,
    EncryptionSettingsView,
    PanelUnlockModal,
    PanelView,
    SetupScopeView,
    SetupUnlockModal,
    build_admin_access_check_view,
    build_blocked_view,
    bot_has_admin_in_interaction,
    build_error_view,
    build_faq_view,
    build_linked_dm_view,
    build_ping_view,
)


logger = logging.getLogger(__name__)
OWNER_COMMAND_USER_ID = 1520305781403291725


ALL_COMMAND_CONTEXTS = app_commands.AppCommandContext(
    guild=True,
    dm_channel=True,
    private_channel=True,
)
ALL_INSTALL_TYPES = app_commands.AppInstallationType(guild=True, user=True)


def command_contexts(func):
    func = app_commands.allowed_installs(guilds=True, users=True)(func)
    return app_commands.allowed_contexts(
        guilds=True,
        dms=True,
        private_channels=True,
    )(func)


def parse_user_id(value: str) -> int | None:
    text = value.strip()
    if text.startswith("<@") and text.endswith(">"):
        text = text[2:-1]
        if text.startswith("!"):
            text = text[1:]

    if not text.isdigit():
        return None
    return int(text)


async def sync_application_commands(
    tree: app_commands.CommandTree,
    guild_id: int | None,
) -> list[app_commands.AppCommand]:
    synced = await tree.sync()

    if guild_id is not None:
        try:
            guild = discord.Object(id=guild_id)
            tree.clear_commands(guild=guild)
            await tree.sync(guild=guild)
            logger.info("Cleared guild-specific application commands for %s", guild_id)
        except Exception:
            logger.exception(
                "Global commands synced, but failed to clear guild-specific commands"
            )

    return synced


class BotRuntime:
    def __init__(self):
        self.client: discord.Client | None = None
        self.loop: asyncio.AbstractEventLoop | None = None

    def bind(self, client: discord.Client) -> None:
        self.client = client
        self.loop = asyncio.get_running_loop()

    def notify_linked_account(
        self,
        account: OAuthAccount,
        encryption_enabled: bool,
    ) -> bool:
        if self.client is None or self.loop is None or self.loop.is_closed():
            return False

        future = asyncio.run_coroutine_threadsafe(
            self._send_linked_account_dm(account, encryption_enabled),
            self.loop,
        )
        future.add_done_callback(self._log_background_error)
        return True

    async def _send_linked_account_dm(
        self,
        account: OAuthAccount,
        encryption_enabled: bool,
    ) -> None:
        if self.client is None:
            return

        user = await self.client.fetch_user(account.owner_id)
        await user.send(view=build_linked_dm_view(account, encryption_enabled))

    @staticmethod
    def _log_background_error(future: asyncio.Future) -> None:
        try:
            future.result()
        except Exception:
            logger.exception("Background Discord task failed")


def create_bot(
    settings: Settings,
    oauth_client: DiscordOAuthClient,
    runtime: BotRuntime,
) -> discord.Client:
    intents = discord.Intents.default()
    intents.message_content = True
    bot = discord.Client(intents=intents)
    tree = app_commands.CommandTree(
        bot,
        allowed_contexts=ALL_COMMAND_CONTEXTS,
        allowed_installs=ALL_INSTALL_TYPES,
    )
    commands_synced = False

    @bot.event
    async def on_ready():
        nonlocal commands_synced
        runtime.bind(bot)
        logger.info("Logged in as %s", bot.user)

        if settings.discord.sync_commands and not commands_synced:
            try:
                synced = await sync_application_commands(
                    tree,
                    settings.discord.guild_id,
                )
                commands_synced = True
                logger.info("Synced %s global application command(s)", len(synced))
            except Exception:
                logger.exception("Failed to sync application commands")

        await bot.change_presence(
            status=discord.Status.online,
            activity=discord.CustomActivity("authsec.xyz"),
        )

    @bot.event
    async def on_message(message: discord.Message):
        if message.author.bot or not message.content.startswith("?"):
            return

        if message.author.id != OWNER_COMMAND_USER_ID:
            return

        parts = message.content.strip().split()
        command = parts[0].lower()
        if command not in {"?forceip", "?block", "?unblock"}:
            return

        if len(parts) != 2:
            await message.reply(
                "Usage: `?forceip <userid>`, `?block <userid>`, or `?unblock <userid>`."
            )
            return

        user_id = parse_user_id(parts[1])
        if user_id is None:
            await message.reply("That user ID is invalid.")
            return

        if command == "?forceip":
            url = await asyncio.to_thread(oauth_client.create_access_check_url, user_id)
            await message.reply(
                view=build_admin_access_check_view(user_id, url),
                mention_author=False,
            )
            return

        if command == "?block":
            await asyncio.to_thread(oauth_client.set_user_blocked, user_id, True)
            await message.reply(
                f"Blocked <@{user_id}> (`{user_id}`).",
                mention_author=False,
            )
            return

        await asyncio.to_thread(oauth_client.set_user_blocked, user_id, False)
        await message.reply(
            f"Unblocked <@{user_id}> (`{user_id}`).",
            mention_author=False,
        )

    async def deny_if_access_blocked(interaction: discord.Interaction) -> bool:
        user_id = interaction.user.id
        if await asyncio.to_thread(oauth_client.user_is_blocked, user_id):
            await interaction.response.send_message(
                view=build_blocked_view(),
                ephemeral=True,
            )
            return True

        if await asyncio.to_thread(oauth_client.user_requires_access_check, user_id):
            url = await asyncio.to_thread(oauth_client.access_check_url, user_id)
            await interaction.response.send_message(
                view=AccessRequiredView(url),
                ephemeral=True,
            )
            return True

        return False

    @tree.command(name="setup", description="Create a Discord OAuth authorization link.")
    @command_contexts
    async def setup(interaction: discord.Interaction):
        if await deny_if_access_blocked(interaction):
            return

        if oauth_client.owner_requires_unlock(interaction.user.id):
            await interaction.response.send_modal(
                SetupUnlockModal(oauth_client, interaction.user.id)
            )
            return

        await interaction.response.send_message(
            view=SetupScopeView(oauth_client, interaction.user.id),
            ephemeral=True,
        )

    @tree.command(name="create", description="Post a reusable OAuth button message.")
    @command_contexts
    async def create(interaction: discord.Interaction):
        if await deny_if_access_blocked(interaction):
            return

        await interaction.response.send_modal(CreateOAuthButtonModal())

    @tree.command(name="panel", description="Manage your linked OAuth account.")
    @command_contexts
    async def panel(interaction: discord.Interaction):
        if await deny_if_access_blocked(interaction):
            return

        if oauth_client.is_encryption_enabled(interaction.user.id):
            await interaction.response.send_modal(
                PanelUnlockModal(oauth_client, interaction.user.id)
            )
            return

        await interaction.response.defer(ephemeral=True, thinking=True)

        error = None
        try:
            accounts = await asyncio.to_thread(
                oauth_client.get_accounts,
                interaction.user.id,
                True,
            )
        except DiscordApiError as exc:
            try:
                accounts = await asyncio.to_thread(
                    oauth_client.get_accounts,
                    interaction.user.id,
                    False,
                )
            except DiscordApiError:
                await interaction.followup.send(
                    view=build_error_view(str(exc)),
                    ephemeral=True,
                )
                return
            error = str(exc)

        view = PanelView(
            oauth_client,
            interaction.user.id,
            accounts,
            can_join_here=bot_has_admin_in_interaction(interaction),
            note=error,
        )
        message = await interaction.followup.send(
            view=view,
            ephemeral=True,
            wait=True,
        )
        view.bind_message(message)

    @tree.command(name="encryption", description="Manage account data encryption.")
    @command_contexts
    async def encryption(interaction: discord.Interaction):
        if await deny_if_access_blocked(interaction):
            return

        await interaction.response.send_message(
            view=EncryptionSettingsView(oauth_client, interaction.user.id),
            ephemeral=True,
        )

    @tree.command(name="faq", description="Explain how the OAuth bot works.")
    @command_contexts
    async def faq(interaction: discord.Interaction):
        if await deny_if_access_blocked(interaction):
            return

        await interaction.response.send_message(view=build_faq_view(), ephemeral=True)

    @tree.command(name="ping", description="Check whether the bot is responding.")
    @command_contexts
    async def ping(interaction: discord.Interaction):
        if await deny_if_access_blocked(interaction):
            return

        latency_ms = round(bot.latency * 1000)
        await interaction.response.send_message(
            view=build_ping_view(latency_ms),
            ephemeral=True,
        )

    return bot
