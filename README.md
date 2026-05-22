# ipwho-tg-bot

Telegram-бот на Go для проверки IP, доменов, proxy-ключей и подписок.

Бот отвечает в аккуратном коротком формате:

```text
🇷🇺 www.gosuslugi.ru

213.59.253.7

🌍 MaxMind
🇷🇺 RU / Russia
AS12389 / Rostelecom

📍 IPinfo
🇷🇺 RU / Russia / Moscow
AS12389 / PJSC Rostelecom

🔎 Censys
https://search.censys.io/hosts/213.59.253.7
```

## Возможности

| Ввод | Что делает |
|---|---|
| `8.8.8.8` | Геолокация IP |
| `45.150.65.65:443` | Достаёт IP из строки с портом |
| `9/18 — 45.150.65.65:443` | Достаёт IP из произвольного текста |
| `example.com` | Резолвит домен и показывает IP-инфо |
| `vless://...`, `vmess://...`, `trojan://...`, `ss://...` | Парсит ключ и проверяет сервер |
| `https://...` | Загружает подписку и отправляет каждый сервер отдельным сообщением |

Подписки поддерживаются в plain-text, base64, URL-safe base64, Xray JSON и newline-delimited JSON.

Под каждым ответом есть кнопки с эмодзи: `🌐 bgp.he.net`, `🧭 bgp.tools`, `📍 ipinfo.io`, `🔎 Censys`, `📜 whois`, `🛰 AS...`.

Можно отправить сразу несколько разных строк через Enter: IP, домены, ключи и ссылки будут поставлены в очередь и обработаны по порядку.

## Что исправлено

- Бот полностью переписан на Go.
- Ответы отправляются в Telegram HTML mode с экранированием пользовательских данных, поэтому ошибка `Can't parse entities...` больше не должна появляться из-за `_`, `[`, `(` и других символов в названиях серверов.
- `Reserved range` больше не ломает обработку: бот показывает понятное примечание для частных/зарезервированных IP.
- Строки вида `9/18 — 45.150.65.65:443` корректно распознаются.
- Добавлена глобальная очередь: один worker обрабатывает запросы последовательно, а новые запросы ждут своей очереди.
- Гео-запросы внутри одного задания выполняются параллельно, DNS и гео-ответы кешируются.
- Добавлен Censys: всегда есть ссылка, а при наличии API-ключей бот дополнительно показывает найденные сервисы/порты.
- Добавлены эмодзи для стран, статусов, разделов и inline-кнопок.
- Добавлена обработка нескольких разных запросов в одном сообщении через Enter.

## Настройка

Скопируйте пример окружения:

```bash
cp .env.example .env
nano .env
```

Минимально нужен только токен Telegram:

```env
BOT_TOKEN=123456789:AAFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Опциональные переменные:

```env
IPWHO_ACCESS_KEY=your_ipwho_access_key
IPINFO_TOKEN=your_ipinfo_token

CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret

QUEUE_SIZE=128
GEO_CONCURRENCY=8
SUB_MESSAGE_DELAY_MS=450
DNS_CACHE_TTL_MINUTES=30
GEO_CACHE_TTL_MINUTES=10
HWID=your_custom_hwid
```

Если `CENSYS_API_ID` и `CENSYS_API_SECRET` не заданы, Censys всё равно будет добавлен как ссылка.

`GEO_CONCURRENCY` управляет параллельными DNS/geo-запросами внутри одной подписки. Очередь пользователей при этом остаётся последовательной.

## Запуск через Docker

```bash
docker compose up -d --build
```

Логи:

```bash
docker compose logs -f
```

Управление:

| Действие | Команда |
|---|---|
| Запустить | `docker compose up -d` |
| Остановить | `docker compose down` |
| Перезапустить | `docker compose restart` |
| Логи | `docker compose logs -f` |
| Статус | `docker compose ps` |

## Запуск без Docker

Нужен Go 1.22+.

```bash
go run .
```

Сборка бинарника:

```bash
go build -o ipwho-tg-bot .
./ipwho-tg-bot
```

## systemd

Пример сервиса:

```ini
[Unit]
Description=IPWho Telegram Bot
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/ipwho-tg-bot
EnvironmentFile=/home/ubuntu/ipwho-tg-bot/.env
ExecStart=/home/ubuntu/ipwho-tg-bot/ipwho-tg-bot
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Команды:

```bash
go build -o ipwho-tg-bot .
sudo systemctl daemon-reload
sudo systemctl enable ipwho-bot
sudo systemctl restart ipwho-bot
sudo systemctl status ipwho-bot
```

## Структура

```text
ipwho-tg-bot/
├── main.go
├── go.mod
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

## HWID и подписки

Для Remnawave/совместимых панелей бот передаёт:

```text
x-hwid: <machine-id>
x-device-os: Linux
x-ver-os: 6.1
x-device-model: Server
```

HWID определяется так: `HWID` из окружения, затем `/etc/machine-id`, затем MAC-адрес.

User-Agent fallback:

```text
Happ/1.0
v2RayTun/5.0
ClashForAndroid/2.5.12
ClashMeta/1.18.0
ipwho-tg-bot-go/1.0
```
