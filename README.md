# ipwho-tg-bot

Telegram-бот для получения геолокации и сетевой информации по IP-адресу через API [ipwho.is](https://ipwho.is).

---

## Возможности

- Поиск по IPv4 и IPv6
- Команда `/ip <адрес>` или просто отправить IP в чат
- Возвращает: страну, регион, город, координаты, ASN, ISP, организацию, часовой пояс
- Поддержка API-ключа ipwho.is для повышенных лимитов

---

## Требования к ВМ

**Для запуска через Docker (рекомендуется):**
- ОС: Ubuntu 22.04 / Debian 12 (или любой Linux-дистрибутив)
- Docker + Docker Compose
- Git
- Доступ в интернет

**Для запуска без Docker:**
- Python 3.10+
- Git
- Доступ в интернет

---

## 1. Подготовка ВМ

Обновите систему и установите Git:

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

1. Откройте Telegram и найдите [@BotFather](https://t.me/BotFather)
2. Отправьте команду `/newbot`
3. Введите имя бота (например: `My IPWho Bot`)
4. Введите username бота (например: `my_ipwho_bot`) — должен заканчиваться на `bot`
5. Скопируйте выданный токен вида `123456789:AAF...`

---

## 4. Получение API-ключа ipwho.is

API-ключ нужен для снятия лимитов на количество запросов.

1. Зарегистрируйтесь на [ipwho.org](https://www.ipwho.org)
2. Перейдите в личный кабинет → раздел **API Keys**
3. Скопируйте ваш `access_key`

> Без ключа бот работает в бесплатном режиме с ограниченным числом запросов. Ключ можно оставить пустым.

---

## 5. Настройка переменных окружения

Создайте файл `.env` на основе примера:

```bash
cp .env.example .env
```

Откройте для редактирования:

```bash
nano .env
```

Заполните оба значения:

```
BOT_TOKEN=123456789:AAFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
IPWHO_ACCESS_KEY=ваш_ключ_от_ipwho
```

Сохраните: `Ctrl+O`, затем `Enter`, затем `Ctrl+X`.

---

## 6. Запуск через Docker (рекомендуется)

### 6.1. Установка Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

Проверьте установку:

```bash
docker --version
docker compose version
```

### 6.2. Сборка и запуск

```bash
docker compose up -d --build
```

Флаг `-d` запускает контейнер в фоне. После этого бот работает автоматически и перезапускается при перезагрузке ВМ.

### 6.3. Просмотр логов

```bash
docker compose logs -f
```

`Ctrl+C` для выхода из режима просмотра.

### 6.4. Управление контейнером

| Действие | Команда |
|---|---|
| Запустить | `docker compose up -d` |
| Остановить | `docker compose down` |
| Перезапустить | `docker compose restart` |
| Посмотреть логи | `docker compose logs -f` |
| Статус | `docker compose ps` |

### 6.5. Обновление бота

```bash
git pull
docker compose up -d --build
```

---

## 7. Запуск без Docker (альтернатива)

### 7.1. Установка Python

```bash
sudo apt install -y python3 python3-pip python3-venv
```

### 7.2. Создание виртуального окружения

```bash
python3 -m venv venv
source venv/bin/activate
```

### 7.3. Установка зависимостей

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 7.4. Ручной запуск (для проверки)

```bash
python3 bot.py
```

В терминале появится:

```
Bot is running...
```

Нажмите `Ctrl+C` для остановки.

### 7.5. Автозапуск через systemd

Создайте файл сервиса:

```bash
sudo nano /etc/systemd/system/ipwho-bot.service
```

Вставьте содержимое, заменив `/home/ubuntu/ipwho-tg-bot` на ваш реальный путь и `ubuntu` на вашего пользователя:

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

Сохраните: `Ctrl+O`, `Enter`, `Ctrl+X`.

Включите и запустите:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ipwho-bot
sudo systemctl start ipwho-bot
```

Проверьте статус:

```bash
sudo systemctl status ipwho-bot
```

Вы должны увидеть `Active: active (running)`.

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
├── .env.example        # Пример файла конфигурации
├── .env                # Ваш файл конфигурации (не коммитить!)
└── README.md           # Документация
```

---

## Использование бота

После запуска откройте бота в Telegram:

- `/start` — приветствие и инструкция
- `/ip 8.8.8.8` — геолокация по IP
- Отправить `1.1.1.1` в чат — то же самое без команды

Пример ответа:

```
🇺🇸 IP Info: 8.8.8.8
Type: IPv4

Location
Continent: North America (NA)
Country: United States (US)
Region: California (CA)
City: Mountain View
Postal: 94039
Capital: Washington D.C.
Coordinates: 37.386, -122.084
EU member: No

Connection
ASN: 15169
ISP: Google LLC
Organization: Google LLC
Domain: google.com

Timezone
Zone: America/Los_Angeles
UTC offset: -07:00
DST: Yes
```
