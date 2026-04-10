# ipwho-tg-bot

Telegram-бот для анализа IP-адресов, доменов, прокси-ключей и подписок. Использует [ipwho.is](https://ipwho.is) для геолокации.

---

## Возможности

| Ввод | Что делает |
|---|---|
| `8.8.8.8` / `2001:db8::1` | Геолокация IP (ipinfo + MaxMind) |
| `google.com` | Резолв домена → геолокация |
| `vless://...` / `vmess://...` / `trojan://...` | Парсинг ключа + геолокация сервера |
| `https://...` | Загрузка подписки, каждый сервер — отдельное сообщение |

**Форматы подписок:**
- Plain-text (один URI на строку)
- Base64 / URL-safe Base64
- Xray JSON (`{"outbounds": [...]}`)
- Newline-delimited JSON
- Double base64

**Поддерживаемые панели:** Remnawave, Marzban, 3x-ui, Hiddify и любые совместимые.

**HWID (Remnawave):** Бот автоматически определяет HWID из `/etc/machine-id` и передаёт его через заголовки при загрузке подписки — устройство регистрируется на первом запросе.

**Кнопки под каждым ответом:** `bgp.he.net` · `bgp.tools` · `ipinfo.io` · `whois` · `AS{номер}`

---

## Требования к ВМ

**Docker (рекомендуется):**
- Ubuntu 22.04 / Debian 12 или любой Linux
- Docker + Docker Compose
- Git

**Без Docker:**
- Python 3.10+
- Git

---

## 1. Подготовка ВМ

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git
```

---

## 2. Клонирование репозитория

```bash
git clone https://github.com/<your-username>/ipwho-tg-bot.git
cd ipwho-tg-bot
```

> Замените `<your-username>` на ваш GitHub-логин.

---

## 3. Получение токена Telegram-бота

1. Найдите [@BotFather](https://t.me/BotFather) в Telegram
2. Отправьте `/newbot`
3. Введите имя и username бота (username должен заканчиваться на `bot`)
4. Скопируйте токен вида `123456789:AAF...`

---

## 4. Получение API-ключа ipwho.is (опционально)

Нужен для снятия лимитов на запросы геолокации.

1. Зарегистрируйтесь на [ipwho.org](https://www.ipwho.org)
2. Перейдите в личный кабинет → **API Keys**
3. Скопируйте `access_key`

> Без ключа бот работает в бесплатном режиме. Ключ можно не указывать.

---

## 5. Настройка переменных окружения

```bash
cp .env.example .env
nano .env
```

Заполните файл:

```env
# Обязательно
BOT_TOKEN=123456789:AAFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Опционально — ключ ipwho.is для повышенных лимитов
IPWHO_ACCESS_KEY=ваш_ключ

# Опционально — переопределить HWID (по умолчанию читается из /etc/machine-id)
# HWID=your_custom_hwid
```

Сохраните: `Ctrl+O` → `Enter` → `Ctrl+X`.

---

## 6. Запуск через Docker (рекомендуется)

### 6.1. Установка Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

Проверьте:

```bash
docker --version
docker compose version
```

### 6.2. Сборка и запуск

```bash
docker compose up -d --build
```

Бот запускается в фоне и автоматически поднимается при перезагрузке ВМ.

### 6.3. Просмотр логов

```bash
docker compose logs -f
```

### 6.4. Управление

| Действие | Команда |
|---|---|
| Запустить | `docker compose up -d` |
| Остановить | `docker compose down` |
| Перезапустить | `docker compose restart` |
| Логи | `docker compose logs -f` |
| Статус | `docker compose ps` |

### 6.5. Обновление

```bash
git pull
docker compose up -d --build
```

---

## 7. Запуск без Docker

### 7.1. Установка Python

```bash
sudo apt install -y python3 python3-pip python3-venv
```

### 7.2. Виртуальное окружение

```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 7.3. Запуск

```bash
python3 bot.py
```

### 7.4. Автозапуск через systemd

```bash
sudo nano /etc/systemd/system/ipwho-bot.service
```

Вставьте, заменив путь и пользователя на свои:

```ini
[Unit]
Description=IPWho Telegram Bot
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/ipwho-tg-bot
EnvironmentFile=/home/ubuntu/ipwho-tg-bot/.env
ExecStart=/home/ubuntu/ipwho-tg-bot/venv/bin/python3 bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable ipwho-bot
sudo systemctl start ipwho-bot
sudo systemctl status ipwho-bot
```

Обновление:

```bash
git pull
pip install -r requirements.txt
sudo systemctl restart ipwho-bot
```

---

## Структура проекта

```
ipwho-tg-bot/
├── bot.py              # Основной код бота
├── Dockerfile          # Docker-образ
├── docker-compose.yml  # Docker Compose конфигурация
├── requirements.txt    # Python-зависимости
├── .env.example        # Пример конфигурации
├── .env                # Конфигурация (не коммитить!)
└── README.md
```

---

## Примеры ответов

### IP / домен

```
🇺🇸 8.8.8.8

ipinfo
org: AS15169 Google LLC
hostname: google.com
timezone: America/Los_Angeles

MaxMind
country: United States (US) 🇺🇸
city: California, Mountain View
coordinates: 37.3861, -122.0839
type: IPv4

[ bgp.he.net ] [ bgp.tools ]
[ ipinfo.io  ] [ whois     ]
[    AS15169              ]
```

### VLESS / VMess / Trojan ключ

```
VLESS — My Server

Server
Host: example.com
Port: 443
UUID: xxxxxxxx-...

Transport
Network: ws
Security: tls
SNI: example.com
...

ipinfo 🇩🇪
ip: 1.2.3.4
org: AS12345 Hetzner Online GmbH
hostname: static.1.2.3.4.hetzner.com
timezone: Europe/Berlin

MaxMind
country: Germany (DE)
city: Bavaria, Nuremberg
coordinates: 49.4478, 11.0683

[ bgp.he.net ] [ bgp.tools ]
[ ipinfo.io  ] [ whois     ]
[    AS12345              ]
```

### Подписка

```
📋 Подписка — 5 серверов
Получаю геолокацию...

1/5           ← отдельное сообщение
VLESS — DE-1
...

2/5           ← отдельное сообщение
VMESS — US-2
...

📋 Подписка — 5 серверов ✓
```

---

## HWID и Remnawave

Бот передаёт HWID через заголовки при каждом запросе подписки:

```
x-hwid: <machine-id>
x-device-os: Linux
x-device-model: Server
User-Agent: Happ/1.0
```

HWID определяется автоматически (`/etc/machine-id` → MAC-адрес → `HWID` из `.env`).  
При первом запросе устройство регистрируется в панели автоматически.

Если сервер отклонил запрос — бот покажет причину (`лимит устройств` / `HWID не принят`) и выведет HWID для ручной регистрации в панели провайдера.

**UA fallback:** если один User-Agent вернул нераспознаваемый ответ, бот автоматически пробует следующий из цепочки: `Happ → v2RayTun → ClashForAndroid → ClashMeta → python-httpx`.
