# Email OSINT Discord Bot

A comprehensive Discord bot that allows you to check emails for associated social media accounts, data breaches, pastes, and more!

## Features

1. **Social Media Account Check**: Using Holehe, the bot can check for associated social media accounts linked with an email address.
2. **Data Breach Check**: Using the HaveIBeenPwned API, the bot checks if the email address has been involved in any known data breaches.
3. **Pastes Check**: The bot also checks if the email address has been listed in any public pastes.
4. **Password Breach Check**: Verify how many times a given password hash has been breached.

## Installation

### Prerequisites

- Python 3.6 or higher
- A valid Discord bot token
- HaveIBeenPwned API key for data breach and pastes checks

### Steps

1. **Clone the repository**:
   ```
   git clone https://github.com/RocketGod-git/email-osint-discord-bot.git
   cd email-osint-discord-bot
   ```

2. **Setup Configuration**:
   - Edit `config.json`.
   - Fill in the required fields:
     - `discord_bot_token`: Your Discord bot token.
     - `hibp_api_key`: Your HaveIBeenPwned API key.

3. **Run the bot**:
   - For Windows users:
     ```
     run.bat
     ```
   - For Linux/Mac users:
     ```
     chmod +x run.sh
     ./run.sh
     ```

## Usage

1. **Email Check**:
   ```
   /email [email_address]
   ```
   This command will check the email address for associated social media accounts, data breaches, and pastes.

2. **Password Hash Check**:
   ```
   /passhash [password_hash]
   ```
   Check how many times a password hash has been breached. Provide at least the first 5 characters of the password hash.

## Credits

- [Holehe](https://github.com/megadose/holehe) for providing the ability to check for associated social media accounts.
- [HaveIBeenPwned](https://haveibeenpwned.com/) for the data breach and pastes checks.

## Contribution

Feel free to fork the repository and submit pull requests. All contributions are welcome!

## License

This project is licensed under the [AGPL-3.0 license](https://github.com/RocketGod-git/email-osint-discord-bot/blob/main/LICENSE).

![rocketgod_logo](https://github.com/RocketGod-git/shodanbot/assets/57732082/7929b554-0fba-4c2b-b22d-6772d23c4a18)