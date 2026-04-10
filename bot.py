import asyncio
import base64
import json
import logging
import os
import re
import socket
import uuid
from urllib.parse import parse_qs, quote, unquote, urlparse

import httpx
from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
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

# Delay between per-server messages to respect Telegram rate limits
SUB_MESSAGE_DELAY = 0.4


def get_hwid() -> str:
    """Return a stable machine identifier to pass with subscription requests."""
    # 1. Explicit override via env
    if val := os.getenv("HWID"):
        return val
    # 2. Linux machine-id
    try:
        with open("/etc/machine-id") as f:
            return f.read().strip()
    except OSError:
        pass
    # 3. MAC-address based fallback (cross-platform)
    return uuid.UUID(int=uuid.getnode()).hex


HWID = get_hwid()
logger.info("HWID: %s", HWID)

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
VLESS_RE = re.compile(r"vless://\S+", re.IGNORECASE)
# Match any http/https URL anywhere in the message
URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)

PROXY_PREFIXES = ("vless://", "vmess://", "trojan://", "ss://")

# User-Agents tried in order when fetching a subscription.
# If the first returns an unrecognisable body, the next is tried automatically.
SUBSCRIPTION_UA_CHAIN = [
    # Happ — reference Remnawave HWID client
    "Happ/1.0",
    # v2RayTun — another HWID-aware client
    "v2RayTun/5.0",
    # Clash-based clients (very common, some panels serve Clash YAML to these)
    "ClashForAndroid/2.5.12",
    "ClashMeta/1.18.0",
    # Generic bare request — some panels serve base64 only to unknown UA
    "python-httpx/0.27.0",
]


# ---------------------------------------------------------------------------
# HTTP request/response logging hooks
# ---------------------------------------------------------------------------
async def _log_request(request: httpx.Request) -> None:
    logger.info("→ %s %s", request.method, request.url)


async def _log_response(response: httpx.Response) -> None:
    logger.info("← %s %s %s", response.status_code, response.request.method, response.request.url)


def _make_client(**kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        event_hooks={"request": [_log_request], "response": [_log_response]},
        **kwargs,
    )


# ---------------------------------------------------------------------------
# ipwho.is API
# ---------------------------------------------------------------------------
async def fetch_ip_info(ip: str) -> dict:
    url = f"{IPWHO_BASE_URL}/{ip}"
    params = {"access_key": IPWHO_ACCESS_KEY} if IPWHO_ACCESS_KEY else {}
    async with _make_client(timeout=10) as client:
        response = await client.get(url, params=params)
        if response.status_code == 404:
            return response.json()
        if response.status_code != 200:
            response.raise_for_status()
        return response.json()


# ---------------------------------------------------------------------------
# Inline keyboard
# ---------------------------------------------------------------------------
def make_keyboard(ip: str, asn) -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton("bgp.he.net", url=f"https://bgp.he.net/ip/{ip}"),
            InlineKeyboardButton("bgp.tools", url=f"https://bgp.tools/prefix/{ip}"),
        ],
        [
            InlineKeyboardButton("ipinfo.io", url=f"https://ipinfo.io/{ip}"),
            InlineKeyboardButton("whois", url=f"https://who.is/whois/{ip}"),
        ],
    ]
    if asn and str(asn) != "N/A":
        rows.append([
            InlineKeyboardButton(f"AS{asn}", url=f"https://bgp.he.net/AS{asn}"),
        ])
    return InlineKeyboardMarkup(rows)


# ---------------------------------------------------------------------------
# Lookup links (text, used in subscription list)
# ---------------------------------------------------------------------------
def lookup_links(ip: str, asn) -> str:
    links = [
        f"[bgp.he.net](https://bgp.he.net/ip/{ip})",
        f"[bgp.tools](https://bgp.tools/prefix/{ip})",
        f"[ipinfo](https://ipinfo.io/{ip})",
        f"[whois](https://who.is/whois/{ip})",
    ]
    if asn and str(asn) != "N/A":
        links.append(f"[AS{asn}](https://bgp.he.net/AS{asn})")
    return " · ".join(links)


# ---------------------------------------------------------------------------
# IP info formatter
# ---------------------------------------------------------------------------
def format_ip_info(data: dict, header: str | None = None) -> str:
    if not data.get("success"):
        return f"Error: {data.get('message', 'Unknown error')}"

    flag = data.get("flag", {}).get("emoji", "")
    tz = data.get("timezone", {})
    conn = data.get("connection", {})
    ip = data.get("ip", "")
    asn = conn.get("asn", "N/A")

    title = header if header else f"{flag} *{ip}*"

    return "\n".join([
        title,
        "",
        "*ipinfo*",
        f"org: AS{asn} {conn.get('org', conn.get('isp', 'N/A'))}",
        f"hostname: {conn.get('domain', 'N/A')}",
        f"timezone: {tz.get('id', 'N/A')}",
        "",
        "*MaxMind*",
        f"country: {data.get('country', 'N/A')} ({data.get('country_code', '')}) {flag}",
        f"city: {data.get('region', 'N/A')}, {data.get('city', 'N/A')}",
        f"coordinates: {data.get('latitude')}, {data.get('longitude')}",
        f"type: `{data.get('type', 'N/A')}`",
    ])


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
# Proxy parsers
# ---------------------------------------------------------------------------
def parse_vless(uri: str) -> dict | None:
    try:
        parsed = urlparse(uri)
        if parsed.scheme.lower() != "vless":
            return None
        qs = parse_qs(parsed.query)

        def qget(key: str) -> str:
            return qs.get(key, ["N/A"])[0]

        return {
            "proto": "vless",
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


def parse_vmess(uri: str) -> dict | None:
    try:
        b64 = uri[8:]  # strip "vmess://"
        b64 += "=" * (-len(b64) % 4)
        data = json.loads(base64.b64decode(b64).decode("utf-8"))
        return {
            "proto": "vmess",
            "uuid": data.get("id", "N/A"),
            "host": data.get("add", "N/A"),
            "port": data.get("port", "N/A"),
            "name": data.get("ps", "N/A"),
            "security": data.get("tls", "N/A") or "none",
            "sni": data.get("sni", "N/A"),
            "type": data.get("net", "N/A"),
            "path": data.get("path", "N/A"),
            "fingerprint": data.get("fp", "N/A"),
            "flow": "N/A",
            "public_key": "N/A",
            "short_id": "N/A",
        }
    except Exception as exc:
        logger.warning("Failed to parse VMess URI: %s", exc)
        return None


def parse_trojan(uri: str) -> dict | None:
    try:
        parsed = urlparse(uri)
        if parsed.scheme.lower() != "trojan":
            return None
        qs = parse_qs(parsed.query)

        def qget(key: str) -> str:
            return qs.get(key, ["N/A"])[0]

        return {
            "proto": "trojan",
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
            "public_key": "N/A",
            "short_id": "N/A",
        }
    except Exception as exc:
        logger.warning("Failed to parse Trojan URI: %s", exc)
        return None


def parse_proxy_uri(line: str) -> dict | None:
    line = line.strip()
    lo = line.lower()
    if lo.startswith("vless://"):
        return parse_vless(line)
    if lo.startswith("vmess://"):
        return parse_vmess(line)
    if lo.startswith("trojan://"):
        return parse_trojan(line)
    return None


# ---------------------------------------------------------------------------
# VLESS / generic proxy formatter (single key)
# ---------------------------------------------------------------------------
def format_proxy_detail(v: dict, geo: dict, ip: str) -> str:
    conn = geo.get("connection", {}) if geo.get("success") else {}
    tz = geo.get("timezone", {}) if geo.get("success") else {}
    flag = geo.get("flag", {}).get("emoji", "") if geo.get("success") else ""
    asn = conn.get("asn", "N/A")
    proto = v.get("proto", "proxy").upper()

    lines = [
        f"*{proto} — {v['name']}*",
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
            f"*ipinfo* {flag}",
            f"ip: `{ip}`",
            f"org: AS{asn} {conn.get('org', conn.get('isp', 'N/A'))}",
            f"hostname: {conn.get('domain', 'N/A')}",
            f"timezone: {tz.get('id', 'N/A')}",
            "",
            "*MaxMind*",
            f"country: {geo.get('country', 'N/A')} ({geo.get('country_code', '')})",
            f"city: {geo.get('region', 'N/A')}, {geo.get('city', 'N/A')}",
            f"coordinates: {geo.get('latitude')}, {geo.get('longitude')}",
        ]
    else:
        lines += ["", f"_Geolocation unavailable: {geo.get('message', 'unknown error')}_"]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Subscription body parsers
# ---------------------------------------------------------------------------
def _try_b64(data: str) -> list[str] | None:
    """Try standard and URL-safe base64 decode; return proxy lines or None."""
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = data + "=" * (-len(data) % 4)
            decoded = decoder(padded.encode()).decode("utf-8")
            lines = [l.strip() for l in decoded.splitlines() if l.strip()]
            if any(l.lower().startswith(PROXY_PREFIXES) for l in lines):
                return lines
        except Exception:
            continue
    return None


def _parse_xray_json(raw: str) -> list[str] | None:
    """
    Parse Xray/sing-box JSON subscription formats.
    Supports:
      - {"outbounds": [...]}  — Xray full config
      - [{"protocol": ..., ...}, ...]  — array of outbound objects
      - newline-delimited JSON objects (one per line)
    Returns a list of proxy:// URI strings, or None if not Xray JSON.
    """
    def outbound_to_uri(ob: dict) -> str | None:
        proto = ob.get("protocol", ob.get("type", "")).lower()
        tag = ob.get("tag", ob.get("name", "N/A"))

        if proto == "vless":
            settings = ob.get("settings", {})
            vnext = settings.get("vnext", [{}])[0]
            address = vnext.get("address", "")
            port = vnext.get("port", 0)
            user = vnext.get("users", [{}])[0]
            uid = user.get("id", "")
            flow = user.get("flow", "")
            ss = ob.get("streamSettings", {})
            network = ss.get("network", "tcp")
            security = ss.get("security", "none")
            reality = ss.get("realitySettings", {})
            tls = ss.get("tlsSettings", {})
            sni = reality.get("serverName", tls.get("serverName", ""))
            fp = reality.get("fingerprint", "")
            pbk = reality.get("publicKey", "")
            sid = reality.get("shortId", "")
            params = {"security": security, "type": network, "flow": flow,
                      "sni": sni, "fp": fp, "pbk": pbk, "sid": sid}
            qs = "&".join(f"{k}={v}" for k, v in params.items() if v)
            name = unquote(tag)
            return f"vless://{uid}@{address}:{port}?{qs}#{quote(name)}"

        if proto in ("vmess",):
            # Xray vmess is encoded separately; reconstruct standard vmess URI
            settings = ob.get("settings", {})
            vnext = settings.get("vnext", [{}])[0]
            address = vnext.get("address", "")
            port = vnext.get("port", 0)
            user = vnext.get("users", [{}])[0]
            uid = user.get("id", "")
            ss = ob.get("streamSettings", {})
            network = ss.get("network", "tcp")
            security = ss.get("security", "none")
            tls_s = ss.get("tlsSettings", {})
            sni = tls_s.get("serverName", "")
            ws = ss.get("wsSettings", {})
            path = ws.get("path", "")
            host = ws.get("headers", {}).get("Host", "")
            vmess_obj = {
                "v": "2", "ps": tag, "add": address, "port": str(port),
                "id": uid, "net": network, "tls": security, "sni": sni,
                "path": path, "host": host, "type": "none",
            }
            b64 = base64.b64encode(json.dumps(vmess_obj).encode()).decode()
            return f"vmess://{b64}"

        if proto == "trojan":
            settings = ob.get("settings", {})
            servers = settings.get("servers", [{}])[0]
            address = servers.get("address", "")
            port = servers.get("port", 0)
            password = servers.get("password", "")
            ss = ob.get("streamSettings", {})
            network = ss.get("network", "tcp")
            security = ss.get("security", "none")
            tls_s = ss.get("tlsSettings", {})
            sni = tls_s.get("serverName", "")
            params = {"security": security, "type": network, "sni": sni}
            qs = "&".join(f"{k}={v}" for k, v in params.items() if v)
            return f"trojan://{password}@{address}:{port}?{qs}#{quote(tag)}"

        return None

    # Try full JSON object / array
    try:
        data = json.loads(raw)
        outbounds = []
        if isinstance(data, dict):
            outbounds = data.get("outbounds", [])
        elif isinstance(data, list):
            outbounds = data

        # Filter out non-proxy outbounds (freedom, blackhole, dns, etc.)
        skip = {"freedom", "blackhole", "dns", "loopback", "direct"}
        uris = []
        for ob in outbounds:
            if ob.get("protocol", ob.get("type", "")).lower() in skip:
                continue
            uri = outbound_to_uri(ob)
            if uri:
                uris.append(uri)
        if uris:
            return uris
    except (json.JSONDecodeError, Exception):
        pass

    # Try newline-delimited JSON (one outbound object per line)
    try:
        uris = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            ob = json.loads(line)
            uri = outbound_to_uri(ob)
            if uri:
                uris.append(uri)
        if uris:
            return uris
    except Exception:
        pass

    return None


def _parse_body(raw: str) -> tuple[list[str] | None, str]:
    """
    Detect and parse a subscription body.
    Returns (lines, format_name) or (None, "unknown").
    """
    # 1. Plain proxy URIs (most common — one per line)
    plain = [l.strip() for l in raw.splitlines() if l.strip()]
    if any(l.lower().startswith(PROXY_PREFIXES) for l in plain):
        return plain, "plain-text"

    # 2. Xray / sing-box JSON
    result = _parse_xray_json(raw)
    if result:
        return result, "xray-json"

    # 3. Base64-encoded body
    result = _try_b64(raw)
    if result:
        return result, "base64"

    # 4. Double-encoded — each line is base64
    for line in plain:
        result = _try_b64(line)
        if result:
            return result, "base64-per-line"

    return None, "unknown"


# ---------------------------------------------------------------------------
# Subscription fetcher (with UA fallback chain)
# ---------------------------------------------------------------------------
async def fetch_subscription_lines(url: str) -> tuple[list[str], dict]:
    """
    Fetch subscription with Remnawave HWID headers.
    Tries each UA in SUBSCRIPTION_UA_CHAIN until the response parses successfully.
    Returns (proxy_lines, last_response_headers).
    """
    base_headers = {
        "x-hwid": HWID,
        "x-device-os": "Linux",
        "x-ver-os": "6.1",
        "x-device-model": "Server",
    }

    last_resp_headers: dict = {}
    last_raw: str = ""

    for attempt, ua in enumerate(SUBSCRIPTION_UA_CHAIN, start=1):
        headers = {**base_headers, "User-Agent": ua}
        logger.info("Subscription attempt %d/%d  UA=%r  url=%s  HWID=%s",
                    attempt, len(SUBSCRIPTION_UA_CHAIN), ua, url, HWID)
        try:
            async with _make_client(timeout=20, follow_redirects=True) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                raw = response.text.strip()
                last_resp_headers = dict(response.headers)
                last_raw = raw
        except httpx.HTTPStatusError as exc:
            logger.warning("Attempt %d HTTP %s, trying next UA", attempt, exc.response.status_code)
            continue
        except httpx.RequestError as exc:
            logger.warning("Attempt %d network error: %s, trying next UA", attempt, exc)
            continue

        # Log Remnawave HWID response headers
        logger.info(
            "HWID response: active=%s not_supported=%s max_reached=%s limit=%s",
            last_resp_headers.get("x-hwid-active", ""),
            last_resp_headers.get("x-hwid-not-supported", ""),
            last_resp_headers.get("x-hwid-max-devices-reached", ""),
            last_resp_headers.get("x-hwid-limit", ""),
        )

        lines, fmt = _parse_body(raw)
        if lines:
            logger.info("Subscription parsed as %r with UA=%r: %d lines", fmt, ua, len(lines))
            return lines, last_resp_headers

        logger.warning("Attempt %d UA=%r: body unrecognised (preview=%r), trying next UA",
                       attempt, ua, raw[:80])

    # All UAs failed — return raw lines so caller can show the error
    logger.error("All UA attempts failed for %s  preview=%r", url, last_raw[:120])
    plain_fallback = [l.strip() for l in last_raw.splitlines() if l.strip()]
    return plain_fallback, last_resp_headers


async def geo_for_host(host: str) -> tuple[str, dict]:
    """Resolve host → IP → geo. Returns (ip, geo_dict)."""
    try:
        if DOMAIN_RE.match(host):
            ip = await resolve_domain(host)
        elif IP_RE.match(host):
            ip = host
        else:
            ip = host
        geo = await fetch_ip_info(ip)
        return ip, geo
    except Exception as exc:
        logger.warning("geo_for_host(%s) failed: %s", host, exc)
        return host, {"success": False, "message": str(exc)}


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    logger.info("User %s (@%s) started the bot", user.id, user.username)
    text = (
        "*IPWho Bot*\n\n"
        "Просто отправь — бот сам определит тип:\n\n"
        "• IPv4 / IPv6 — геолокация + ссылки\n"
        "• Домен — resolve → геолокация\n"
        "• `vless://` / `vmess://` / `trojan://` — анализ ключа\n"
        "• Ссылка на подписку (`https://...`) — список серверов\n\n"
        "_Команды не нужны — просто отправь данные._"
    )
    await update.message.reply_text(text, parse_mode="Markdown")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    raw = update.message.text.strip()
    user = update.effective_user

    # 1. Subscription URL — search anywhere in the message
    url_match = URL_RE.search(raw)
    if url_match:
        logger.info("User %s (%s) → subscription URL", user.id, user.username)
        await subscription_and_reply(update, url_match.group(0))
        return

    # 2. VLESS/VMess/Trojan — search anywhere in the message
    for prefix in PROXY_PREFIXES:
        pattern = re.compile(re.escape(prefix) + r"\S+", re.IGNORECASE)
        m = pattern.search(raw)
        if m:
            logger.info("User %s (%s) → proxy URI (%s)", user.id, user.username, prefix)
            await proxy_and_reply(update, m.group(0))
            return

    # 3. First token — IP or domain
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
            "• Прокси-ключ: `vless://...` / `vmess://...` / `trojan://...`\n"
            "• Ссылку на подписку: `https://...`",
            parse_mode="Markdown",
        )


# ---------------------------------------------------------------------------
# Core lookup helpers
# ---------------------------------------------------------------------------
async def ip_and_reply(update: Update, ip: str) -> None:
    msg = await update.message.reply_text(f"Ищу `{ip}`...", parse_mode="Markdown")
    try:
        data = await fetch_ip_info(ip)
        asn = data.get("connection", {}).get("asn", "N/A")
        result = format_ip_info(data)
        logger.info("IP OK: %s → %s, %s", ip, data.get("country"), data.get("city"))
        await msg.edit_text(result, parse_mode="Markdown", reply_markup=make_keyboard(ip, asn))
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
        await msg.edit_text(f"`{domain}` → `{ip}`, получаю гео...", parse_mode="Markdown")
        data = await fetch_ip_info(ip)
        flag = data.get("flag", {}).get("emoji", "")
        asn = data.get("connection", {}).get("asn", "N/A")
        header = f"{flag} *Домен: {domain}* (`{ip}`)"
        result = format_ip_info(data, header=header)
        logger.info("Domain OK: %s → %s, %s, %s", domain, ip, data.get("country"), data.get("city"))
        await msg.edit_text(result, parse_mode="Markdown", reply_markup=make_keyboard(ip, asn))
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


async def proxy_and_reply(update: Update, uri: str) -> None:
    msg = await update.message.reply_text("Анализирую ключ...")
    try:
        v = parse_proxy_uri(uri)
        if not v:
            await msg.edit_text(
                "Не удалось разобрать ключ. Поддерживаются: `vless://`, `vmess://`, `trojan://`.",
                parse_mode="Markdown",
            )
            return

        host = v["host"]
        logger.info("%s host: %s:%s  name: %s", v["proto"], host, v["port"], v["name"])

        await msg.edit_text(f"Резолвлю `{host}`...", parse_mode="Markdown")
        ip, geo = await geo_for_host(host)

        asn = geo.get("connection", {}).get("asn", "N/A") if geo.get("success") else "N/A"
        result = format_proxy_detail(v, geo, ip)
        logger.info("%s OK: host=%s ip=%s country=%s", v["proto"], host, ip, geo.get("country"))
        await msg.edit_text(result, parse_mode="Markdown", reply_markup=make_keyboard(ip, asn))
    except Exception as exc:
        logger.exception("Unexpected error processing proxy URI")
        await msg.edit_text(f"Ошибка: {exc}")


def _is_error_entry(v: dict) -> bool:
    """Return True if this proxy entry is a server-side error placeholder."""
    host = str(v.get("host", ""))
    port = str(v.get("port", ""))
    name = str(v.get("name", "")).lower()
    error_keywords = ("not supported", "contact support", "app not supported",
                      "unsupported", "register", "activate")
    return (
        host in ("0.0.0.0", "127.0.0.1", "::1", "")
        or port in ("0", "1", "")
        or any(kw in name for kw in error_keywords)
    )


async def subscription_and_reply(update: Update, url: str) -> None:
    msg = await update.message.reply_text("Загружаю подписку...")
    try:
        lines, resp_hdrs = await fetch_subscription_lines(url)
        all_proxies = [p for line in lines if (p := parse_proxy_uri(line)) is not None]

        # Separate valid entries from error placeholders
        error_entries = [p for p in all_proxies if _is_error_entry(p)]
        proxies = [p for p in all_proxies if not _is_error_entry(p)]

        if error_entries and not proxies:
            # Determine exact reason from Remnawave response headers
            if resp_hdrs.get("x-hwid-max-devices-reached") == "true":
                reason = "Превышен лимит устройств для этой подписки."
            elif resp_hdrs.get("x-hwid-not-supported") == "true":
                reason = "Клиент не поддерживает HWID (заголовок x-hwid не принят сервером)."
            else:
                reason = "HWID не зарегистрирован или не принят сервером."

            names = ", ".join(e["name"] for e in error_entries[:3])
            logger.warning(
                "Subscription error entries: %s  reason=%s  HWID=%s  url=%s",
                names, reason, HWID, url,
            )
            await msg.edit_text(
                f"Сервер отклонил запрос.\n\n"
                f"*Причина:* {reason}\n\n"
                f"Ответ сервера: _{names}_\n\n"
                f"HWID этого бота:\n`{HWID}`",
                parse_mode="Markdown",
            )
            return

        if not proxies:
            await msg.edit_text(
                "В подписке не найдено поддерживаемых ключей (vless, vmess, trojan)."
            )
            return

        total = len(proxies)
        logger.info("Subscription: %d valid servers (%d errors filtered)  HWID=%s  url=%s",
                    total, len(error_entries), HWID, url)

        # Update status message → header
        await msg.edit_text(
            f"📋 *Подписка — {total} серверов*\nПолучаю геолокацию...",
            parse_mode="Markdown",
        )

        # Process and send each server as a separate message
        for i, v in enumerate(proxies, start=1):
            try:
                ip, geo = await geo_for_host(v["host"])
                asn = geo.get("connection", {}).get("asn", "N/A") if geo.get("success") else "N/A"
                text = format_proxy_detail(v, geo, ip)
                # Prepend index
                text = f"*{i}/{total}*\n\n" + text
                await update.message.reply_text(
                    text,
                    parse_mode="Markdown",
                    reply_markup=make_keyboard(ip, asn),
                )
                logger.info("Sub server %d/%d: %s ip=%s country=%s",
                            i, total, v["host"], ip, geo.get("country"))
            except Exception as exc:
                logger.warning("Sub server %d/%d (%s) failed: %s", i, total, v["host"], exc)
                await update.message.reply_text(
                    f"*{i}/{total}* — `{v['host']}:{v['port']}`\n_Ошибка: {exc}_",
                    parse_mode="Markdown",
                )

            # Respect Telegram rate limit between messages
            if i < total:
                await asyncio.sleep(SUB_MESSAGE_DELAY)

        # Update header to final state
        await msg.edit_text(f"📋 *Подписка — {total} серверов* ✓", parse_mode="Markdown")
        logger.info("Subscription OK: %d servers, url=%s", total, url)

    except httpx.HTTPStatusError as exc:
        logger.error("HTTP %s fetching subscription %s", exc.response.status_code, url)
        await msg.edit_text(f"Ошибка загрузки подписки: HTTP {exc.response.status_code}")
    except httpx.RequestError as exc:
        logger.error("Network error fetching subscription: %s", exc)
        await msg.edit_text(f"Сетевая ошибка: {exc}")
    except Exception as exc:
        logger.exception("Unexpected error processing subscription")
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
