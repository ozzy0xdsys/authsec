# handles the discord bot and the server, which handles the bot callback

import json
import discord
from discord import app_commands
from discord.ext import commands
from tinydb import *
import threading
from flask import Flask, request
import asyncio
from urllib.parse import urlencode

app = Flask(__name__)

db = TinyDB("database.json", indent=4)

client = commands.Bot(command_prefix="!", intents=discord.Intents.all())

with open("config.json", "r") as f:
    config = json.load(f)


def checkuserdb(user):
    User = Query()

    # checks if the user is already in the db. if not, put them in
    if not db.contains(User.userid == user.id):
        db.insert({
            "userid": user.id,
            "saved_oauth": {}
        })





@client.event
async def on_ready():
    print(f"Logged in as {client.user}")

    try:
        synced = await client.tree.sync()
        print(f"Synced {len(synced)} command(s)")
    except Exception as e:
        print(f"Sync failed: {e}")










class AccountSetupModal(discord.ui.Modal, title="Setup OAuth installation"):
    def __init__(self):
        super().__init__()

        self.scopes = discord.ui.Select(
            options=[
                discord.SelectOption(
                    label="See user's Email",
                    value="email",
                    emoji="✉️",
                    default=True,
                    description="Get the email address linked to their Discord"
                ),
                discord.SelectOption(
                    label="See user's Connections",
                    value="connections",
                    emoji="🎮",
                    description="See their linked social/gaming accounts"
                ),
                discord.SelectOption(
                    label="See user's Guilds",
                    value="guilds",
                    emoji="🏠",
                    default=True,
                    description="Show the guilds/servers this user is in"
                ),
                discord.SelectOption(
                    label="Join guilds",
                    value="guilds.join",
                    emoji="➡️",
                    description="Get the user to join guilds. Bot must be admin in the server."
                ),
                discord.SelectOption(
                    label="View friends",
                    value="relationships.read",
                    emoji="💬",
                    description="See who this user is friends with"
                ),
            ],
            required=True,
            min_values=1,
            max_values=5
        )

        self.add_item(discord.ui.Label(text="OAuth Scopes", component=self.scopes))


    
    async def on_submit(self, interaction: discord.Interaction):
        self.scopes.values.append("identify")

        params = {
            "client_id": "1512553567037423656",
            "response_type": "code",
            "redirect_uri": "https://spiz.lol",
            "scope": " ".join(self.scopes.values),
        }

        oauthlink = "https://discord.com/oauth2/authorize?" + urlencode(params) + "&state=" + str(interaction.user.id)


        await interaction.response.send_message(
            oauthlink,
            ephemeral=True
        )








class OAuthView(discord.ui.LayoutView):
    def __init__(self, title: str, description: str, link: str, color):
        super().__init__()

        self.container = discord.ui.Container(
            discord.ui.TextDisplay(f"## {title}\n{description}"),

            discord.ui.Separator(
                spacing=discord.SeparatorSpacing.small
            ),

            discord.ui.ActionRow(
                discord.ui.Button(
                    label="Authorize",
                    url=link,
                    style=discord.ButtonStyle.link
                )
            ),

            accent_color=color
        )

        self.add_item(self.container)








class EmbedGenModal(discord.ui.Modal, title="Embed Generator"):
    def __init__(self):
        super().__init__()

        self.color = discord.ui.Select(
            placeholder="Color on the site of the embed",
            options=[
                discord.SelectOption(
                    label="Blue",
                    value="blue",
                    emoji="🟦",
                    default=True
                ),
                discord.SelectOption(
                    label="Red",
                    value="red",
                    emoji="🟥",
                    default=False
                ),
                discord.SelectOption(
                    label="Yellow",
                    value="yellow",
                    emoji="🟨"
                ),
                discord.SelectOption(
                    label="Green",
                    value="green",
                    emoji="🟩"
                ),
                discord.SelectOption(
                    label="Orange",
                    value="orange",
                    emoji="🟧"
                )
            ],
            min_values=1,
            max_values=1,
            required=True
        )

        self.etitle = discord.ui.TextInput(
            label="Title",
            placeholder="Title on the embed"
        )

        self.description = discord.ui.TextInput(
            label="Description",
            style=discord.TextStyle.paragraph,
            placeholder="Description on embed"
        )

        self.link = discord.ui.TextInput(
            label="OAuth Link",
            placeholder="https://discord.com/oauth2/..."
        )

        self.add_item(self.etitle)
        self.add_item(self.description)
        self.add_item(discord.ui.Label(text="Color", component=self.color))
        self.add_item(self.link)



    async def on_submit(self, interaction: discord.Interaction):
        color = {
            "blue": discord.Color.blue(),
            "red": discord.Color.red(),
            "yellow": discord.Color.yellow(),
            "green": discord.Color.green(),
            "orange": discord.Color.orange(),
        }[self.color.values[0]]

        view = OAuthView(
            title=self.etitle.value,
            description=self.description.value,
            link=self.link.value,
            color=color
        )

        await interaction.response.send_message(view=view)







@client.tree.command(name="create", description="Generate an embed which allows you to put your OAuth link as a button")
@app_commands.allowed_contexts(True, True, True)
async def embedgen(interaction: discord.Interaction):

    checkuserdb(interaction.user)

    await interaction.response.send_modal(EmbedGenModal())




@client.tree.command(name="faq", description="See how we operate")
@app_commands.allowed_contexts(True, True, True)
async def faqcmd(interaction: discord.Interaction):


    User = Query()

    # checks if the user is already in the db. if not, put them in
    if not db.contains(User.userid == interaction.user.id):
        db.insert({
            "userid": interaction.user.id,
            "saved_oauth": {}
        })


    embed = discord.Embed(
        title="Frequently Asked Questions",
        description="Read this over fully so you know how we store your data and how this bot works.",
        colour=discord.Color.blurple()
    )

    embed.add_field(
        name="Data storage",
        value="We store your user ID and the access/refresh tokens for accounts you have. This is all stored in plain text, but will never be shared with anyone else or use it ourself."
    )

    embed.add_field(
        name="How does this bot work?",
        value=(
            "For OAuth Installation, it generates a Discord app installation link that when clicked on any device, opens a modal, if the user accepts this, it will generate an "
            "[Access Token](https://docs.discord.com/developers/platform/oauth2-and-permissions#oauth2-user-token)"
            " which allows the bot to interact with the user's account, but you'd only be able to do things that you selected and the user allowed."
        )
    )

    embed.add_field(
        name="OAuth Extra Info",
        value=(
            "Because of how complex this is, an extra section is needed.\n\n"
            "Every time you access/configure user info, a new access/refresh token is generated. A refresh token is only valid for 30 days. So unfortunately, if you are inactive for too long, you will no longer have access to the user's info."
        )
    )

    embed.add_field(
        name="What are scopes?",
        value=(
            "[OAuth Scopes](https://docs.discord.com/developers/platform/oauth2-and-permissions#scopes) are requested during the OAuth2 authorization flow and must be declared in the form when you run </setup:1512737902021312602>. They are like permissions, saying what you are allowed to do."
        ),
        inline=False
    )

    embed.add_field(
        name="How do I add users?",
        value=(
            "To add users easily, run the </create:1518730315911397497> command with your OAuth link copied to clipboard. Most importantly, enter your OAuth link to the provided text entry. Add the title, description and color. When you click submit, it will immediately be sent to the channel. You can forward the message anywhere you'd like and the button is usable infinite times."
        )
    )

    await interaction.response.send_message(embed=embed, ephemeral=True)

@client.tree.command(name="setup", description="Begin setting up your OAuth installation link")
@app_commands.allowed_contexts(True, True, True)
async def setup(interaction: discord.Interaction):

    checkuserdb(interaction.user)
    
    # show setup modal
    await interaction.response.send_modal(AccountSetupModal())


@app.route("/callback")
def callback():
    return "test123abc"


def run_flask():
    app.run(host="0.0.0.0", port=80)

if __name__ == "__main__":
    # Start Flask
    threading.Thread(target=run_flask, daemon=True).start()

    # Start Discord bot
    asyncio.run(client.run(config["token"]))