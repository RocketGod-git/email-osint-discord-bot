# __________                  __             __     ________             .___ 
# \______   \  ____    ____  |  | __  ____ _/  |_  /  _____/   ____    __| _/ 
#  |       _/ /  _ \ _/ ___\ |  |/ /_/ __ \\   __\/   \  ___  /  _ \  / __ |  
#  |    |   \(  <_> )\  \___ |    < \  ___/ |  |  \    \_\  \(  <_> )/ /_/ |  
#  |____|_  / \____/  \___  >|__|_ \ \___  >|__|   \______  / \____/ \____ |  
#         \/              \/      \/     \/               \/              \/  
#
# Email OSINT Discord Bot by RocketGod
# https://github.com/RocketGod-git/email-osint-discord-bot

import json
import logging
import re
import datetime
import aiohttp
import asyncio
import discord
from src import modules as holehe_modules

logging.basicConfig(level=logging.DEBUG)

def load_config():
    try:
        with open('config.json', 'r') as file:
            config = json.load(file)
            if "discord_bot_token" not in config:
                logging.error("Configuration file is missing the 'discord_bot_token' key.")
                return None
            return config
    except FileNotFoundError:
        logging.error("Configuration file 'config.json' not found.")
        return None
    except json.JSONDecodeError:
        logging.error("Error decoding the configuration file. Ensure 'config.json' is a valid JSON file.")
        return None
    except Exception as e:
        logging.error(f"Unexpected error loading configuration: {e}")
        return None

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
HIBP_PASSWORD_API_BASE = "https://api.pwnedpasswords.com"

config = load_config()

if not config:
    logging.error("Failed to load configuration. Exiting...")
    exit()

class aclient(discord.Client):
    def __init__(self) -> None:
        super().__init__(intents=discord.Intents.default())
        self.tree = discord.app_commands.CommandTree(self)
        self.activity = discord.Activity(type=discord.ActivityType.watching, name="/email | /passhash")
        self.discord_message_limit = 2000
        self.session = None

    async def on_ready(self):
        print(f"Bot {self.user.name} is ready!")
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60))
        await self.tree.sync()
        logging.info(f'{self.user} is online.')

    async def close(self):
        try:
            await super().close()
        finally:
            if self.session:
                await self.session.close()

    async def send_split_messages(self, interaction, message: str, require_response=True):
        """Sends a message, and if it's too long for Discord, splits it."""
        if not message.strip():
            logging.warning("Attempted to send an empty message.")
            return

        if query := next(
            (
                option.get("value", "")
                for option in interaction.data.get("options", [])
                if option.get("name") == "query"
            ),
            "",
        ):
            prepend_text = f"Query: {query}\n\n"
        else:
            prepend_text = ""
        lines = message.split("\n")
        chunks = []
        current_chunk = ""

        if prepend_text:
            current_chunk += prepend_text

        for line in lines:
            if len(current_chunk) + len(line) + 1 > self.discord_message_limit:
                chunks.append(current_chunk)
                current_chunk = line + "\n"
            else:
                current_chunk += line + "\n"

        if current_chunk:
            chunks.append(current_chunk)

        if not chunks:
            logging.warning("No chunks generated from the message.")
            return

        try:
            await interaction.followup.send(chunks[0])
            chunks = chunks[1:]  
        except Exception as e:
            logging.error(f"Failed to send the first chunk. Error: {e}")
            try:
                await interaction.followup.send(chunks[0])
                chunks = chunks[1:]  
            except Exception as e_followup:
                logging.error(f"Failed to send the first chunk using followup. Error: {e_followup}")

        for chunk in chunks:
            try:
                await interaction.channel.send(chunk)
            except Exception as e:
                logging.error(f"Failed to send a message chunk to the channel. Error: {e}")

    async def handle_errors(self, interaction, error, error_type="Error"):
        error_message = f"{error_type}: {error}"
        logging.error(f"Error for user {interaction.user}: {error_message}")
        
        friendly_message = "An unexpected error occurred. Please try again later."
        
        try:
            if interaction.response.is_done():
                await interaction.followup.send(friendly_message)
            else:
                await interaction.response.send_message(friendly_message, ephemeral=False)
        except discord.HTTPException as http_err:
            logging.warning(f"HTTP error while responding to {interaction.user}: {http_err}")
            await interaction.followup.send(friendly_message)
        except Exception as unexpected_err:
            logging.error(f"Unexpected error while responding to {interaction.user}: {unexpected_err}")
            await interaction.followup.send(friendly_message)

    async def check_email_with_holehe(self, email, module_data):
        return await holehe_modules.check_email(email, module_data)

    async def get_breaches(self, email, api_key):
        url = f"{HIBP_API_BASE}/breachedaccount/{email}?truncateResponse=false"
        local_headers = {
            "hibp-api-key": api_key,
            "user-agent": "BreachFinder"
        }
        logging.debug(f"Headers for request to {url}: {local_headers}")
        try:
            async with self.session.get(url, headers=local_headers) as response:
                # Log the timestamp
                logging.info(
                    f"Made a request to {url} at {datetime.datetime.now(datetime.timezone.utc)} UTC"
                )

                # Log full response headers and status code
                logging.info(f"Full Response Headers: {response.headers}")
                logging.info(f"Response Status Code: {response.status}")

                # Check rate limit headers and log them
                retry_after = int(response.headers.get('retry-after', 0))
                logging.info(f"Retry after: {retry_after} seconds")

                data = await response.text()
                logging.debug(f"Raw response from API (breaches): {data}")

                if response.status == 200:
                    return await response.json() or []
                elif response.status == 400:
                    logging.error("Bad request. Ensure the email address is in a valid format.")
                    return []
                elif response.status == 401:
                    logging.error("Unauthorized: API key was not provided or is invalid.")
                    return []
                elif response.status == 403:
                    logging.error("Forbidden: User agent is not specified in the request.")
                    return []
                elif response.status == 404:
                    logging.info(f"No breaches found for the account: {email}")
                    return []
                elif response.status == 429:
                    logging.warning(f"Rate limit exceeded. Retrying after {retry_after} seconds.")
                    await asyncio.sleep(retry_after + 1)  
                    return await self.get_breaches(email, api_key)  
                elif response.status == 503:
                    logging.error("Service Unavailable: The server is currently unable to handle the request.")
                    return []
                else:
                    logging.error(f"Unexpected status code: {response.status}. Please check the request.")
                    return []
        except aiohttp.ClientError as ce:
            logging.error(f"Client error while making request to {url}: {ce}")
            return []

    async def get_pastes(self, email, api_key):
        url = f"{HIBP_API_BASE}/pasteaccount/{email}"

        local_headers = {
            "hibp-api-key": api_key,
            "user-agent": "BreachFinder"
        }
        logging.debug(f"Headers for request to {url}: {local_headers}")  

        try:
            async with self.session.get(url, headers=local_headers) as response:
                # Log the timestamp
                logging.info(
                    f"Made a request to {url} at {datetime.datetime.now(datetime.timezone.utc)} UTC"
                )

                # Log full response headers and status code
                logging.info(f"Full Response Headers: {response.headers}")
                logging.info(f"Response Status Code: {response.status}")

                # Check rate limit headers and log them
                retry_after = int(response.headers.get('retry-after', 0))
                logging.info(f"Retry after: {retry_after} seconds")

                data = await response.text()
                logging.debug(f"Raw response from API (pastes): {data}")

                if response.status == 200:
                    return await response.json() or []
                elif response.status == 400:
                    logging.error("Bad request. Ensure the email address is in a valid format.")
                    return []
                elif response.status == 401:
                    logging.error("Unauthorized: API key was not provided or is invalid.")
                    return []
                elif response.status == 403:
                    logging.error("Forbidden: User agent is not specified in the request.")
                    return []
                elif response.status == 404:
                    logging.info(f"No pastes found for the account: {email}")
                    return []
                elif response.status == 429:
                    logging.warning(f"Rate limit exceeded. Retrying after {retry_after} seconds.")
                    await asyncio.sleep(retry_after + 1)  
                    return await self.get_pastes(email, api_key) 
                elif response.status == 503:
                    logging.error("Service Unavailable: The server is currently unable to handle the request.")
                    return []
                else:
                    logging.error(f"Unexpected status code: {response.status}. Please check the request.")
                    return []
        except aiohttp.ClientError as ce:
            logging.error(f"Client error while making request to {url}: {ce}")
            return []

    async def get_password_breach_count(self, password_hash_prefix, password_hash):
        url = f"{HIBP_PASSWORD_API_BASE}/range/{password_hash_prefix}"
        local_headers = {
            "hibp-api-key": config.get("hibp_api_key"),
            "user-agent": "BreachFinder"
        }
        logging.debug(f"Headers for request to {url}: {local_headers}")
        try:
            async with self.session.get(url, headers=local_headers) as response:
                # Log the timestamp
                logging.info(
                    f"Made a request to {url} at {datetime.datetime.now(datetime.timezone.utc)} UTC"
                )

                # Log full response headers and status code
                logging.info(f"Full Response Headers: {response.headers}")
                logging.info(f"Response Status Code: {response.status}")

                data = await response.text()
                logging.debug(f"Raw response from API (password breach count): {data}")

                if response.status == 200:
                    lines = data.splitlines()
                    for line in lines:
                        parts = line.rsplit(":", 1)  
                        if len(parts) != 2:
                            logging.warning(f"Unexpected format in line: {line}")
                            continue
                        suffix, count_str = parts
                        full_hash = password_hash_prefix + suffix
                        if password_hash == full_hash:
                            return int(count_str)

                    logging.info(f"No breaches found for the provided password hash prefix: {password_hash_prefix}")
                    return 0

                elif response.status == 401:
                    logging.error("Unauthorized: API key was not provided or is invalid.")
                    return 0
                elif response.status == 403:
                    logging.error("Forbidden: User agent is not specified in the request.")
                    return 0
                elif response.status == 429:
                    retry_after = int(response.headers.get('retry-after', 0))
                    logging.warning(f"Rate limit exceeded. Retrying after {retry_after} seconds.")
                    await asyncio.sleep(retry_after + 1)  
                    return await self.get_password_breach_count(password_hash_prefix, password_hash)
                elif response.status == 503:
                    logging.error("Service Unavailable: The server is currently unable to handle the request.")
                    return 0
                else:
                    logging.error(f"Unexpected status code: {response.status}. Please check the request.")
                    return 0
        except aiohttp.ClientError as ce:
            logging.error(f"Client error while making request to {url}: {ce}")
            return 0

def run_discord_bot(token):
    client = aclient()

    @client.tree.command(name="email", description="Check an email for social media accounts, data breaches, and pastes.")
    async def email_check(interaction: discord.Interaction, email: str):
        logging.info(f"Starting email check for {email}.")

        await interaction.response.defer(ephemeral=False)

        # Checking with Holehe
        all_functions = holehe_modules.get_all_functions_from_holehe()
        logging.info(f"Loaded {len(all_functions)} functions from Holehe for checking.")
        holehe_results = await client.check_email_with_holehe(email, all_functions)

        breaches = None
        pastes = None

        try:
            # Checking with HaveIBeenPwned
            logging.debug(f"Starting HIBP checks for {email}.")
            breaches = await client.get_breaches(email, config["hibp_api_key"])
            await asyncio.sleep(2)  
            pastes = await client.get_pastes(email, config["hibp_api_key"])
            logging.debug(f"Completed HIBP checks for {email}.")
        except aiohttp.ClientResponseError as e:
            logging.error(f"ClientResponseError during HIBP checks for {email}: {e}")
            if e.status == 429:
                await interaction.followup.send("Rate limit exceeded for HaveIBeenPwned API. Please try again later.", ephemeral=False)
                return
            else:
                await client.handle_errors(interaction, e)
        except Exception as unexpected_err:
            logging.error(f"Unexpected error during HIBP checks for {email}: {unexpected_err}", exc_info=True)
            await client.handle_errors(interaction, unexpected_err)

        output_messages = []

        # Process Holehe results
        logging.debug(f"About to process Holehe data for {email}.")
        if holehe_results:
            filtered_results = [res for res in holehe_results if res['exists']]
            if filtered_results:
                formatted_holehe = '\n\n'.join([f"Platform: {res['name']}\nExists: {res['exists']}\nRate Limited: {res['rateLimit']}\nEmail Recovery: {res.get('emailrecovery', 'N/A')}\nPhone Number: {res.get('phoneNumber', 'N/A')}\nOthers: {res.get('others', 'N/A')}" for res in filtered_results])
                output_messages.append(formatted_holehe)
            else:
                output_messages.append(f"No Social Media accounts found for the account: {email}")
        else:
            logging.error(f"Unexpected data from Holehe for {email}: {holehe_results}")
            output_messages.append(f"No results found with Holehe for the account: {email}")

        # Process HIBP breaches
        logging.debug(f"About to process HIBP breaches data for {email}.")
        logging.debug(f"Raw breaches data for {email}: {breaches}")

        if breaches:
            if not isinstance(breaches, list) or not all(isinstance(breach, dict) for breach in breaches):
                logging.error(f"Unexpected data type/format for HIBP breaches: {breaches}")
                return

            try:
                formatted_breaches = []

                for breach in breaches:
                    # Print each breach for debugging
                    logging.debug(f"Processing breach: {breach}")

                    # Convert HTML links in the description to markdown for Discord
                    desc = breach.get('Description', 'N/A')
                    desc = re.sub(r'<a href="(.*?)" .*?>(.*?)</a>', r'[\2](\1)', desc)

                    breach_details = [
                        f"**Name:** ``{breach.get('Name', 'N/A')}``",
                        f"**Title:** `{breach.get('Title', 'N/A')}`",
                        f"**Domain:** `{breach.get('Domain', 'N/A')}`",
                        f"**Breach Date:** `{breach.get('BreachDate', 'N/A')}`",
                        f"**Added Date:** `{breach.get('AddedDate', 'N/A')}`",
                        f"**Modified Date:** `{breach.get('ModifiedDate', 'N/A')}`",
                        f"**Pwn Count:** `{breach.get('PwnCount', 'N/A')}`",
                        f"**Description:**\n{desc}",
                        f"**Data Classes:** `{', '.join(breach.get('DataClasses', []))}`",
                        f"**Verified:** `{str(breach.get('IsVerified', 'N/A'))}`",
                        f"**Fabricated:** `{str(breach.get('IsFabricated', 'N/A'))}`",
                        f"**Sensitive:** `{str(breach.get('IsSensitive', 'N/A'))}`",
                        f"**Retired:** `{str(breach.get('IsRetired', 'N/A'))}`",
                        f"**Spam List:** `{str(breach.get('IsSpamList', 'N/A'))}`",
                        f"**Malware:** `{str(breach.get('IsMalware', 'N/A'))}`",
                        f"**Subscription Free:** `{str(breach.get('IsSubscriptionFree', 'N/A'))}`",
                        f"**Logo Path:** {breach.get('LogoPath', 'N/A')}"
                    ]

                    # Print formatted breach details for debugging
                    logging.debug("Formatted breach details: " + '\n'.join(breach_details))

                    formatted_breaches.append('\n'.join(breach_details))

                separator = "\n\n" + '-'*40
                output_messages.append(
                    f"BREACHES:{separator}{separator.join(formatted_breaches)}"
                )

            except TypeError:
                logging.error(f"Unexpected data format for breaches: {breaches}")

        elif breaches is not None:  
            output_messages.append(f"No breaches found for the account: {email}")

        # Process HIBP pastes
        logging.debug(f"About to process HIBP pastes data for {email}.")

        if pastes:
            # Check if pastes is a list and each of its items is a dictionary
            if not isinstance(pastes, list) or not all(isinstance(paste, dict) for paste in pastes):
                logging.error(f"Unexpected data type/format for HIBP pastes: {pastes}")
                return

            try:
                formatted_pastes = []

                for paste in pastes:
                    paste_details = [
                        "Source: " + str(paste.get('Source', 'N/A')),
                        "Id: " + str(paste.get('Id', 'N/A')),
                        "Title: " + (str(paste.get('Title')) if paste.get('Title') is not None else 'No title'),
                        "Date: " + str(paste.get('Date', 'N/A')),
                        "Email Count: " + str(paste.get('EmailCount', 'N/A'))
                    ]
                    formatted_pastes.append('\n'.join(paste_details))

                separator = "\n\n" + '-'*40
                output_messages.append(
                    f"PASTES:{separator}"
                    + "\n\n"
                    + separator.join(formatted_pastes)
                )
            except TypeError:
                logging.error(f"Unexpected data format for pastes: {str(pastes)}")
        elif pastes is not None:  
            output_messages.append(f"No pastes found for the account: {email}")

        # Send results
        logging.debug(f"Preparing to send results for {email}.")
        output_messages.append(f"## Report finished for target: `{email}`")
        final_output = '\n\n'.join(output_messages)
        if final_output:
            await client.send_split_messages(interaction, final_output)
        else:
            await interaction.followup.send(f"No results found for {email}.", ephemeral=False)

        logging.info(f"Completed email check for {email}.")

    @client.tree.command(name="passhash", description="Check how many times a password hash has been breached.")
    async def password_hash_check(interaction: discord.Interaction, password_hash: str):
        await interaction.response.defer(ephemeral=False)
        try:
            hash_prefix = password_hash[:5]
            if len(password_hash) < 5:
                await interaction.followup.send("Please provide at least the first 5 characters of the password hash.", ephemeral=False)
                return

            # We assume the hash is SHA-1 and the HIBP API requires only the first 5 characters of the hash. Probably needs more work.
            count = await client.get_password_breach_count(hash_prefix, password_hash)

            if count:
                await interaction.followup.send(f"The password hash has been found {count} times in breaches.", ephemeral=False)
            else:
                await interaction.followup.send("The password hash was not found in breaches.", ephemeral=False)
        except Exception as unexpected_err:
            await client.handle_errors(interaction, unexpected_err)

    try:
        client.run(token)
    finally:
        asyncio.run(client.close())

if __name__ == "__main__":
    run_discord_bot(config.get("discord_bot_token"))
