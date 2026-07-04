from __future__ import annotations

import asyncio
import logging

import discord
from discord import app_commands
from discord.ext import commands

from .models import OAuthAccount
from .oauth import DiscordApiError, DiscordOAuthClient
from .settings import Settings
from .ui import (
    CreateOAuthButtonModal,
    PanelView,
    SetupScopeView,
    build_faq_embed,
    build_linked_dm_embed,
    build_panel_embed,
    build_setup_embed,
)


logger = logging.getLogger(__name__)


class BotRuntime:
    def __init__(self):
        self.client: commands.Bot | None = None
        self.loop: asyncio.AbstractEventLoop | None = None

    def bind(self, client: commands.Bot) -> None:
        self.client = client
        self.loop = asyncio.get_running_loop()

    def notify_linked_account(self, account: OAuthAccount) -> bool:
        if self.client is None or self.loop is None or self.loop.is_closed():
            return False

        future = asyncio.run_coroutine_threadsafe(
            self._send_linked_account_dm(account),
            self.loop,
        )
        future.add_done_callback(self._log_background_error)
        return True

    async def _send_linked_account_dm(self, account: OAuthAccount) -> None:
        if self.client is None:
            return

        user = await self.client.fetch_user(account.owner_id)
        await user.send(embed=build_linked_dm_embed(account))

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
) -> commands.Bot:
    intents = discord.Intents.default()
    bot = commands.Bot(command_prefix=settings.discord.command_prefix, intents=intents)
    commands_synced = False

    @bot.event
    async def on_ready():
        nonlocal commands_synced
        runtime.bind(bot)
        logger.info("Logged in as %s", bot.user)

        if settings.discord.sync_commands and not commands_synced:
            try:
                if settings.discord.guild_id:
                    guild = discord.Object(id=settings.discord.guild_id)
                    bot.tree.copy_global_to(guild=guild)
                    synced = await bot.tree.sync(guild=guild)
                else:
                    synced = await bot.tree.sync()

                commands_synced = True
                logger.info("Synced %s application command(s)", len(synced))
            except Exception:
                logger.exception("Failed to sync application commands")

        await bot.change_presence(
            status=discord.Status.online,
            activity=discord.CustomActivity("authsec.xyz"),
        )

    @bot.tree.command(name="setup", description="Create a Discord OAuth authorization link.")
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def setup(interaction: discord.Interaction):
        await interaction.response.send_message(
            embed=build_setup_embed(),
            view=SetupScopeView(oauth_client, interaction.user.id),
            ephemeral=True,
        )

    @bot.tree.command(name="create", description="Post a reusable OAuth button message.")
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def create(interaction: discord.Interaction):
        await interaction.response.send_modal(CreateOAuthButtonModal())

    @bot.tree.command(name="panel", description="Manage your linked OAuth account.")
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def panel(interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)

        error = None
        try:
            account = await asyncio.to_thread(
                oauth_client.get_account,
                interaction.user.id,
                True,
            )
        except DiscordApiError as exc:
            account = await asyncio.to_thread(
                oauth_client.get_account,
                interaction.user.id,
                False,
            )
            error = str(exc)

        await interaction.followup.send(
            embed=build_panel_embed(account, error),
            view=PanelView(
                oauth_client,
                interaction.user.id,
                account,
                can_join_here=interaction.guild is not None,
            ),
            ephemeral=True,
        )

    @bot.tree.command(name="faq", description="Explain how the OAuth bot works.")
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def faq(interaction: discord.Interaction):
        await interaction.response.send_message(embed=build_faq_embed(), ephemeral=True)

    @bot.tree.command(name="ping", description="Check whether the bot is responding.")
    @app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
    async def ping(interaction: discord.Interaction):
        latency_ms = round(bot.latency * 1000)
        await interaction.response.send_message(
            f"Pong. Gateway latency: {latency_ms}ms.",
            ephemeral=True,
        )

    return bot
