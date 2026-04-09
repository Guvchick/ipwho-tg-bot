import asyncio
import logging
import os
import re
import socket
from urllib.parse import parse_qs, unquote, urlparse

import httpx
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

load_dotenv()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ipwho-bot")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BOT_TOKEN = os.getenv("BOT_TOKEN")
IPWHO_ACCESS_KEY = os.getenv("IPWHO_ACCESS_KEY", "")
IPWHO_BASE_URL = "https://ipwho.is"

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
IP_RE = re.compile(
    r"^("
    r"(\d{1,3}\.){3}\d{1,3}"                       # IPv4
    r"|"
    r"([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"   # IPv6
    r")$"
)
DOMAIN_RE = re.compile(r"^(?!-)([a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$")

# Matches a vless:// URI anywhere in the message (URI ends at whitespace)
VLESS_RE = re.compile(r"vless://\S+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# ipwho.is API
# ---------------------------------------------------------------------------
async def fetch_ip_info(ip: str) -> dict:
    url = f"{IPWHO_BASE_URL}/{ip}"
    params = {"access_key": IPWHO_ACCESS_KEY} if IPWHO_ACCESS_KEY else {}
    logger.info("API request → %s", ip)
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(url, params=params)
        if response.status_code == 404:
            return response.json()
        if response.status_code != 200:
            response.raise_for_status()
        return response.json()


def lookup_links(ip: str, asn) -> str:
    """Return Markdown links to lookup services."""
    links = [
        f"[bgp.he.net](https://bgp.he.net/ip/{ip})",
        f"[ipinfo](https://ipinfo.io/{ip})",
        f"[whois](https://who.is/whois/{ip})",
    ]
    if asn and asn != "N/A":
        links.append(f"[AS{asn}](https://bgp.he.net/AS{asn})")
    return " · ".join(links)


def format_ip_info(data: dict, header: str | None = None) -> str:
    if not data.get("success"):
        return f"Error: {data.get('message', 'Unknown error')}"

    flag = data.get("flag", {}).get("emoji", "")
    tz = data.get("timezone", {})
    conn = data.get("connection", {})
    ip = data.get("ip", "")
    asn = conn.get("asn", "N/A")

    title = header if header else f"{flag} *IP: {ip}*"

    lines = [
        title,
        f"Type: `{data.get('type', 'N/A')}`",
        "",
        "*Location*",
        f"Country: {data.get('country', 'N/A')} ({data.get('country_code', '')}) {flag}",
        f"Region: {data.get('region', 'N/A')} ({data.get('region_code', '')})",
        f"City: {data.get('city', 'N/A')}",
        f"Postal: {data.get('postal', 'N/A')}",
        f"Coordinates: {data.get('latitude')}, {data.get('longitude')}",
        f"EU: {'Yes' if data.get('is_eu') else 'No'}",
        "",
        "*Network*",
        f"ASN: AS{asn}",
        f"ISP: {conn.get('isp', 'N/A')}",
        f"Org: {conn.get('org', 'N/A')}",
        f"Domain: {conn.get('domain', 'N/A')}",
        "",
        "*Timezone*",
        f"Zone: {tz.get('id', 'N/A')} ({tz.get('utc', 'N/A')})",
        f"DST: {'Yes' if tz.get('is_dst') else 'No'}",
        "",
        f"*BGP:* {lookup_links(ip, asn)}",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Domain resolution
# ---------------------------------------------------------------------------
async def resolve_domain(domain: str) -> str:
    loop = asyncio.get_event_loop()
    logger.info("Resolving domain: %s", domain)
    ip = await loop.run_in_executor(None, socket.gethostbyname, domain)
    logger.info("  %s → %s", domain, ip)
    return ip


# ---------------------------------------------------------------------------
# VLESS parser
# ---------------------------------------------------------------------------
def parse_vless(uri: str) -> dict | None:
    """Parse a vless:// URI. Format: vless://<uuid>@<host>:<port>?<params>#<name>"""
    try:
        parsed = urlparse(uri)
        if parsed.scheme.lower() != "vless":
            return None

        qs = parse_qs(parsed.query)

        def qget(key: str) -> str:
            vals = qs.get(key, [])
            return vals[0] if vals else "N/A"

        return {
            "uuid": parsed.username or "N/A",
            "host": parsed.hostname or "N/A",
            "port": parsed.port or "N/A",
            "name": unquote(parsed.fragment) if parsed.fragment else "N/A",
            "security": qget("security"),
            "sni": qget("sni"),
            "type": qget("type"),
            "path": qget("path"),
            "fingerprint": qget("fp"),
            "flow": qget("flow"),
            "public_key": qget("pbk"),
            "short_id": qget("sid"),
        }
    except Exception as exc:
        logger.warning("Failed to parse VLESS URI: %s", exc)
        return None


def format_vless(v: dict, geo: dict, ip: str) -> str:
    conn = geo.get("connection", {}) if geo.get("success") else {}
    tz = geo.get("timezone", {}) if geo.get("success") else {}
    flag = geo.get("flag", {}).get("emoji", "") if geo.get("success") else ""
    asn = conn.get("asn", "N/A")

    lines = [
        f"*VLESS — {v['name']}*",
        "",
        "*Server*",
        f"Host: `{v['host']}`",
        f"Port: `{v['port']}`",
        f"UUID: `{v['uuid']}`",
        "",
        "*Transport*",
        f"Network: `{v['type']}`",
        f"Security: `{v['security']}`",
        f"SNI: `{v['sni']}`",
        f"Path: `{v['path']}`",
        f"Fingerprint: `{v['fingerprint']}`",
        f"Flow: `{v['flow']}`",
        f"Public Key: `{v['public_key']}`",
        f"Short ID: `{v['short_id']}`",
    ]

    if geo.get("success"):
        lines += [
            "",
            f"*Geolocation {flag}*",
            f"IP: `{ip}`",
            f"Country: {geo.get('country', 'N/A')} ({geo.get('country_code', '')})",
            f"Region: {geo.get('region', 'N/A')}",
            f"City: {geo.get('city', 'N/A')}",
            f"ISP: {conn.get('isp', 'N/A')}",
            f"ASN: AS{asn}",
            f"Org: {conn.get('org', 'N/A')}",
            f"Timezone: {tz.get('id', 'N/A')} ({tz.get('utc', 'N/A')})",
            "",
            f"*BGP:* {lookup_links(ip, asn)}",
        ]
    else:
        lines += ["", f"_Geolocation unavailable: {geo.get('message', 'unknown error')}_"]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    logger.info("User %s (@%s) started the bot", user.id, user.username)
    text = (
        "*IPWho Bot*\n\n"
        "Просто отправь мне что-нибудь из этого — бот сам определит тип:\n\n"
        "• IPv4 / IPv6 — геолокация + BGP\n"
        "• Домен — resolve → геолокация + BGP\n"
        "• `vless://` ключ — параметры сервера + геолокация + BGP\n\n"
        "_Команды не нужны — просто отправь данные._"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    raw = update.message.text.strip()
    user = update.effective_user

    # 1. VLESS — search anywhere in the message
    vless_match = VLESS_RE.search(raw)
    if vless_match:
        logger.info("User %s (%s) → VLESS URI detected", user.id, user.username)
        await vless_and_reply(update, vless_match.group(0))
        return

    # 2. Take the first token (handles accidental trailing spaces / newlines)
    token = raw.split()[0] if raw.split() else raw

    if IP_RE.match(token):
        logger.info("User %s (%s) → IP: %s", user.id, user.username, token)
        await ip_and_reply(update, token)
    elif DOMAIN_RE.match(token):
        logger.info("User %s (%s) → domain: %s", user.id, user.username, token)
        await domain_and_reply(update, token.lower())
    else:
        logger.info("User %s (%s) → unrecognised: %r", user.id, user.username, raw[:60])
        await update.message.reply_text(
            "Не могу определить тип. Отправь:\n"
            "• IP-адрес: `8.8.8.8`\n"
            "• Домен: `google.com`\n"
            "• VLESS-ключ: `vless://...`",
            parse_mode="Markdown",
        )


# ---------------------------------------------------------------------------
# Core lookup helpers
# ---------------------------------------------------------------------------
async def ip_and_reply(update: Update, ip: str) -> None:
    msg = await update.message.reply_text(f"Ищу `{ip}`...", parse_mode="Markdown")
    try:
        data = await fetch_ip_info(ip)
        result = format_ip_info(data)
        logger.info("IP OK: %s → %s, %s", ip, data.get("country"), data.get("city"))
        await msg.edit_text(result, parse_mode="Markdown")
    except httpx.HTTPStatusError as exc:
        logger.error("HTTP %s for IP %s", exc.response.status_code, ip)
        await msg.edit_text(f"HTTP ошибка: {exc.response.status_code}")
    except httpx.RequestError as exc:
        logger.error("Network error for IP %s: %s", ip, exc)
        await msg.edit_text(f"Сетевая ошибка: {exc}")
    except Exception as exc:
        logger.exception("Unexpected error for IP %s", ip)
        await msg.edit_text(f"Ошибка: {exc}")


async def domain_and_reply(update: Update, domain: str) -> None:
    msg = await update.message.reply_text(f"Резолвлю `{domain}`...", parse_mode="Markdown")
    try:
        ip = await resolve_domain(domain)
        await msg.edit_text(f"Резолв: `{domain}` → `{ip}`, получаю гео...", parse_mode="Markdown")
        data = await fetch_ip_info(ip)
        flag = data.get("flag", {}).get("emoji", "")
        header = f"{flag} *Домен: {domain}* (`{ip}`)"
        result = format_ip_info(data, header=header)
        logger.info("Domain OK: %s → %s, %s, %s", domain, ip, data.get("country"), data.get("city"))
        await msg.edit_text(result, parse_mode="Markdown")
    except socket.gaierror:
        logger.warning("Cannot resolve domain: %s", domain)
        await msg.edit_text(f"Не удалось резолвнуть домен: `{domain}`", parse_mode="Markdown")
    except httpx.HTTPStatusError as exc:
        logger.error("HTTP %s for domain %s", exc.response.status_code, domain)
        await msg.edit_text(f"HTTP ошибка: {exc.response.status_code}")
    except httpx.RequestError as exc:
        logger.error("Network error for domain %s: %s", domain, exc)
        await msg.edit_text(f"Сетевая ошибка: {exc}")
    except Exception as exc:
        logger.exception("Unexpected error for domain %s", domain)
        await msg.edit_text(f"Ошибка: {exc}")


async def vless_and_reply(update: Update, uri: str) -> None:
    msg = await update.message.reply_text("Анализирую VLESS ключ...")
    try:
        v = parse_vless(uri)
        if not v:
            await msg.edit_text(
                "Не удалось разобрать VLESS URI. Убедись, что ключ начинается с `vless://`.",
                parse_mode="Markdown",
            )
            return

        host = v["host"]
        logger.info("VLESS host: %s:%s  name: %s", host, v["port"], v["name"])

        if DOMAIN_RE.match(host):
            await msg.edit_text(f"Резолвлю `{host}`...", parse_mode="Markdown")
            ip = await resolve_domain(host)
        elif IP_RE.match(host):
            ip = host
        else:
            ip = host  # best-effort (e.g., bare hostname)

        geo = await fetch_ip_info(ip)
        result = format_vless(v, geo, ip)
        logger.info("VLESS OK: host=%s ip=%s country=%s", host, ip, geo.get("country"))
        await msg.edit_text(result, parse_mode="Markdown")
    except socket.gaierror:
        logger.warning("VLESS: cannot resolve host")
        await msg.edit_text("Не удалось резолвнуть хост VLESS-сервера.")
    except httpx.RequestError as exc:
        logger.error("VLESS network error: %s", exc)
        await msg.edit_text(f"Сетевая ошибка: {exc}")
    except Exception as exc:
        logger.exception("Unexpected error processing VLESS URI")
        await msg.edit_text(f"Ошибка: {exc}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    if not BOT_TOKEN:
        raise ValueError("BOT_TOKEN не задан. Проверь файл .env.")

    logger.info("Starting bot...")
    if IPWHO_ACCESS_KEY:
        logger.info("ipwho.is access key configured")
    else:
        logger.warning("IPWHO_ACCESS_KEY не задан — работаю в бесплатном режиме (rate-limited)")

    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("Polling started")
    app.run_polling()


if __name__ == "__main__":
    main()
