import os
import re
import httpx
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
IPWHO_BASE_URL = "https://ipwho.is"

IP_PATTERN = re.compile(
    r"^("
    r"(\d{1,3}\.){3}\d{1,3}"           # IPv4
    r"|"
    r"([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"  # IPv6
    r")$"
)


async def fetch_ip_info(ip: str) -> dict:
    url = f"{IPWHO_BASE_URL}/{ip}"
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


def format_ip_info(data: dict) -> str:
    if not data.get("success"):
        message = data.get("message", "Unknown error")
        return f"Error: {message}"

    flag = data.get("flag", {}).get("emoji", "")
    timezone = data.get("timezone", {})
    connection = data.get("connection", {})

    lines = [
        f"{flag} *IP Info: {data.get('ip')}*",
        f"Type: `{data.get('type', 'N/A')}`",
        "",
        "*Location*",
        f"Continent: {data.get('continent', 'N/A')} ({data.get('continent_code', '')})",
        f"Country: {data.get('country', 'N/A')} ({data.get('country_code', '')})",
        f"Region: {data.get('region', 'N/A')} ({data.get('region_code', '')})",
        f"City: {data.get('city', 'N/A')}",
        f"Postal: {data.get('postal', 'N/A')}",
        f"Capital: {data.get('capital', 'N/A')}",
        f"Coordinates: {data.get('latitude')}, {data.get('longitude')}",
        f"EU member: {'Yes' if data.get('is_eu') else 'No'}",
        "",
        "*Connection*",
        f"ASN: {connection.get('asn', 'N/A')}",
        f"ISP: {connection.get('isp', 'N/A')}",
        f"Organization: {connection.get('org', 'N/A')}",
        f"Domain: {connection.get('domain', 'N/A')}",
        "",
        "*Timezone*",
        f"Zone: {timezone.get('id', 'N/A')}",
        f"UTC offset: {timezone.get('utc', 'N/A')}",
        f"DST: {'Yes' if timezone.get('is_dst') else 'No'}",
    ]

    return "\n".join(lines)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "Welcome to *IPWho Bot*!\n\n"
        "Send me an IP address (IPv4 or IPv6) and I'll return detailed geolocation and network information.\n\n"
        "Commands:\n"
        "/ip <address> — look up a specific IP\n"
        "/myip — look up your own IP (not available via Telegram, see note)\n\n"
        "Or just send an IP address directly in chat."
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text(
            "Usage: /ip <address>\nExample: /ip 8.8.8.8"
        )
        return

    ip = context.args[0].strip()
    await lookup_and_reply(update, ip)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text.strip()
    if IP_PATTERN.match(text):
        await lookup_and_reply(update, text)
    else:
        await update.message.reply_text(
            "Please send a valid IPv4 or IPv6 address.\nExample: `8.8.8.8` or `/ip 1.1.1.1`",
            parse_mode="Markdown",
        )


async def lookup_and_reply(update: Update, ip: str) -> None:
    msg = await update.message.reply_text(f"Looking up `{ip}`...", parse_mode="Markdown")
    try:
        data = await fetch_ip_info(ip)
        result = format_ip_info(data)
        await msg.edit_text(result, parse_mode="Markdown")
    except httpx.HTTPStatusError as e:
        await msg.edit_text(f"HTTP error: {e.response.status_code}")
    except httpx.RequestError as e:
        await msg.edit_text(f"Network error: {e}")
    except Exception as e:
        await msg.edit_text(f"Unexpected error: {e}")


def main() -> None:
    if not BOT_TOKEN:
        raise ValueError("BOT_TOKEN is not set. Check your .env file.")

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("ip", ip_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    print("Bot is running...")
    app.run_polling()


if __name__ == "__main__":
    main()
