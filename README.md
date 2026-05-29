# IPWho Robot

**[@ipwho_robot](https://t.me/ipwho_robot)** — Telegram-бот для быстрой разведки IP, доменов, proxy-ключей и VPN-подписок.

Отправьте IP, домен, строку с сервером, proxy URI или ссылку на подписку — бот разберёт ввод, найдёт серверы, покажет географию, ASN, провайдера, сетевые ссылки и transport-детали.

```text
🇩🇪 Berlin Edge
example.net:443

93.184.216.34

🧬 Proxy
protocol: vless
transport: xhttp
security: reality
sni: front.example.net
path: /xhttp
mode: auto
fp: chrome

🌍 MaxMind
🇩🇪 DE / Germany
AS15133 / Edgecast

📍 IPinfo
DE / Germany / Berlin
AS15133 / Edgecast Inc.
```

## Что Умеет

- Проверяет IP-адреса и домены.
- Достаёт IP из произвольных строк вроде `45.150.65.65:443` или `9/18 — 45.150.65.65:443`.
- Парсит proxy-ключи и показывает сервер без раскрытия полного ключа в хранилище.
- Загружает VPN-подписки и отправляет каждый сервер отдельной карточкой.
- Показывает ASN, организацию, страну, город и полезные сетевые ссылки.
- Добавляет кнопки для `bgp.he.net`, `bgp.tools`, `ipinfo.io`, Censys и whois.
- Обрабатывает несколько строк в одном сообщении через очередь.

## Поддерживаемый Ввод

| Ввод | Результат |
|---|---|
| `8.8.8.8` | География, ASN, провайдер и ссылки |
| `example.com` | DNS-резолв и IP-информация |
| `45.150.65.65:443` | Проверка IP из строки с портом |
| `vless://...` | Разбор proxy-сервера |
| `vmess://...` | Разбор VMess-конфига |
| `trojan://...` | Разбор Trojan-конфига |
| `ss://...` | Разбор Shadowsocks |
| `hysteria2://...`, `hy2://...` | Разбор Hysteria2 |
| `tuic://...` | Разбор TUIC |
| `https://...` | Загрузка и разбор подписки |

## Подписки

IPWho Robot понимает популярные форматы подписок:

- plain text
- base64 и URL-safe base64
- Xray JSON
- sing-box-подобный JSON
- newline-delimited JSON

Для `vless`, `vmess` и `trojan` бот вытаскивает transport-детали:

```text
tcp, ws, grpc, xhttp, splithttp, httpupgrade, h2/http, kcp, quic
```

В карточке сервера видны `path`, `host/authority`, `mode`, `serviceName`, `ALPN`, `security`, `SNI`, `flow`, `fingerprint`, Reality `publicKey` и `shortId`.

## Для Кого

**Админам VPN и proxy-сервисов** — быстро проверить, что реально лежит в подписке.

**Сетевым инженерам** — посмотреть ASN, провайдера и внешние сетевые источники за один запрос.

**Пользователям подписок** — понять, куда ведёт ключ и какие серверы внутри.

**Разработчикам ботов и панелей** — получить аккуратный пример обработки proxy URI и подписок на Go.

## Аккуратность

- Полный proxy-ключ не сохраняется в JSON-хранилище.
- Telegram-токены редактируются из логов.
- Ответы экранируются для Telegram HTML mode.
- Частные и зарезервированные IP не ломают ответ, а помечаются предупреждением.
- Логи структурированные: `INFO`, `WARN`, `ERROR`.

## Под Капотом

- Go
- Telegram Bot API
- ipwho.is
- IPinfo
- Censys Platform
- Docker-ready runtime

Для собственного запуска достаточно задать `BOT_TOKEN`; остальные интеграции и лимиты настраиваются через переменные окружения. Подробности можно посмотреть прямо в коде и `docker-compose.yml`.

## Бот

Открыть в Telegram: **[@ipwho_robot](https://t.me/ipwho_robot)**
