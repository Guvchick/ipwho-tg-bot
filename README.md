# ipwho-tg-bot

Telegram-бот для получения геолокации и сетевой информации по IP-адресу через API [ipwho.is](https://ipwho.is).

---

## Возможности

- Поиск по IPv4 и IPv6
- Команда `/ip <адрес>` или просто отправить IP в чат
- Возвращает: страну, регион, город, координаты, ASN, ISP, организацию, часовой пояс

---

## Требования к ВМ

- ОС: Ubuntu 22.04 / Debian 12 (или любой Linux-дистрибутив)
- Python 3.10+
- Git
- Доступ в интернет (для запросов к ipwho.is и Telegram API)

---

## 1. Подготовка ВМ

Обновите систему и установите необходимые пакеты:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3 python3-pip python3-venv
```

Проверьте версию Python (должна быть 3.10+):

```bash
python3 --version
```

---

## 2. Клонирование репозитория

```bash
git clone https://github.com/<your-username>/ipwho-tg-bot.git
cd ipwho-tg-bot
```

> Замените `<your-username>` на ваш GitHub-логин.

---

## 3. Создание виртуального окружения

```bash
python3 -m venv venv
source venv/bin/activate
```

После активации в начале строки терминала появится `(venv)`.

---

## 4. Установка зависимостей

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 5. Получение токена Telegram-бота

1. Откройте Telegram и найдите [@BotFather](https://t.me/BotFather)
2. Отправьте команду `/newbot`
3. Введите имя бота (например: `My IPWho Bot`)
4. Введите username бота (например: `my_ipwho_bot`) — должен заканчиваться на `bot`
5. Скопируйте выданный токен вида `123456789:AAF...`

---

## 6. Настройка переменных окружения

Создайте файл `.env` на основе примера:

```bash
cp .env.example .env
```

Откройте файл для редактирования:

```bash
nano .env
```

Вставьте ваш токен:

```
BOT_TOKEN=123456789:AAFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Сохраните: `Ctrl+O`, затем `Enter`, затем `Ctrl+X`.

---

## 7. Запуск бота

### Ручной запуск (для проверки)

```bash
source venv/bin/activate
python3 bot.py
```

Если всё настроено правильно, в терминале появится:

```
Bot is running...
```

Нажмите `Ctrl+C` для остановки.

---

## 8. Запуск как системный сервис (автозапуск)

Чтобы бот работал в фоне и перезапускался при перезагрузке ВМ, настройте `systemd`-сервис.

### 8.1. Узнайте абсолютный путь к проекту

```bash
pwd
```

Запомните вывод, например: `/home/ubuntu/ipwho-tg-bot`

### 8.2. Создайте файл сервиса

```bash
sudo nano /etc/systemd/system/ipwho-bot.service
```

Вставьте следующее содержимое, заменив `/home/ubuntu/ipwho-tg-bot` на ваш реальный путь и `ubuntu` на вашего пользователя:

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

### 8.3. Включите и запустите сервис

```bash
sudo systemctl daemon-reload
sudo systemctl enable ipwho-bot
sudo systemctl start ipwho-bot
```

### 8.4. Проверьте статус

```bash
sudo systemctl status ipwho-bot
```

Вы должны увидеть `Active: active (running)`.

### 8.5. Просмотр логов

```bash
sudo journalctl -u ipwho-bot -f
```

Флаг `-f` выводит логи в реальном времени. `Ctrl+C` для выхода.

---

## 9. Управление сервисом

| Действие | Команда |
|---|---|
| Запустить | `sudo systemctl start ipwho-bot` |
| Остановить | `sudo systemctl stop ipwho-bot` |
| Перезапустить | `sudo systemctl restart ipwho-bot` |
| Отключить автозапуск | `sudo systemctl disable ipwho-bot` |
| Посмотреть логи | `sudo journalctl -u ipwho-bot -f` |

---

## 10. Обновление бота

Чтобы применить изменения из репозитория:

```bash
cd ipwho-tg-bot
git pull
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart ipwho-bot
```

---

## Структура проекта

```
ipwho-tg-bot/
├── bot.py            # Основной код бота
├── requirements.txt  # Python-зависимости
├── .env.example      # Пример файла конфигурации
├── .env              # Ваш файл конфигурации (не коммитить!)
└── README.md         # Документация
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
Postal: 94043
Capital: Washington D.C.
Coordinates: 37.386, -122.0838
EU member: No

Connection
ASN: AS15169
ISP: Google LLC
Organization: Google LLC
Domain: google.com

Timezone
Zone: America/Los_Angeles
UTC offset: -07:00
DST: Yes
```
