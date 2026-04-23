# SPECTRA — Полная инструкция по развёртыванию и тестированию

## Содержание

0. [Быстрый путь для релиза 0.1.4](#0-быстрый-путь-для-релиза-014)
1. [Что такое SPECTRA и его возможности](#1-что-такое-spectra-и-его-возможности)
2. [Требования](#2-требования)
3. [Быстрый деплой одной командой (рекомендуется)](#3-быстрый-деплой-одной-командой-рекомендуется)
4. [Запуск клиента на Ubuntu Desktop](#4-запуск-клиента-на-ubuntu-desktop)
5. [Ручное развёртывание на VPS (альтернатива)](#5-ручное-развёртывание-на-vps-альтернатива)
6. [Локальное тестирование (клиент + сервер на одной машине)](#6-локальное-тестирование-клиент--сервер-на-одной-машине)
7. [Использование через браузер и приложения](#7-использование-через-браузер-и-приложения)
8. [Docker-развёртывание](#8-docker-развёртывание)
9. [Параметры конфигурации](#9-параметры-конфигурации)
10. [Устранение неполадок](#10-устранение-неполадок)
11. [Безопасность](#11-безопасность)

---

## 0. Быстрый путь для релиза 0.1.4

### VPS-сервер

```bash
sudo apt update
sudo apt install -y git ca-certificates

git clone https://github.com/anyagixx/SPECTRA.git /opt/spectra-src
cd /opt/spectra-src

sudo ./scripts/deploy-server.sh \
  --cert /etc/letsencrypt/live/ВАШ_ДОМЕН/fullchain.pem \
  --key  /etc/letsencrypt/live/ВАШ_ДОМЕН/privkey.pem
```

Скрипт сам установит недостающие утилиты, установит Go при необходимости, соберёт сервер, сгенерирует PSK, включит QUIC tuning, создаст `spectra.service` и запустит его. Секреты сервера хранятся в `/etc/spectra/spectra.env` с правами `600`, а не в аргументах процесса systemd.

### Ubuntu Desktop клиент

```bash
git clone https://github.com/anyagixx/SPECTRA.git ~/SPECTRA
cd ~/SPECTRA

./scripts/client-service.sh install \
  --server ВАШ_ДОМЕН:443 \
  --sni ВАШ_ДОМЕН \
  --psk "PSK_С_СЕРВЕРА"

./scripts/quic-tune.sh enable
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me/ip
```

Клиентские настройки хранятся в `~/.config/spectra/client.env` с правами `600`. Управление:

Чтобы не сохранять PSK в истории shell, можно передать его через переменную `SPECTRA_PSK` вместо аргумента `--psk`.

```bash
./scripts/client-service.sh status
./scripts/client-service.sh logs
./scripts/client-service.sh restart
./scripts/client-service.sh stop
./scripts/client-service.sh uninstall
```

### Включение и отключение QUIC tuning

Не нужно вручную выполнять `sudo cp ... /etc/sysctl.d/`. Используйте:

```bash
./scripts/quic-tune.sh status
./scripts/quic-tune.sh enable
./scripts/quic-tune.sh disable
./scripts/quic-tune.sh restart-client
```

`enable` сохраняет текущие runtime-значения sysctl, устанавливает `/etc/sysctl.d/99-spectra-quic.conf`, применяет настройки и перезапускает `spectra-client`, если он активен. `disable` удаляет persistent-конфиг, применяет sysctl заново, восстанавливает сохранённые runtime-значения, если они есть, и тоже перезапускает клиент.

### Важно про Telegram

Сначала проверяйте прокси через `curl` или браузер. Telegram Desktop может открывать очень много параллельных SOCKS-соединений и IPv6-целей; если после него прокси “завис”, выполните `./scripts/client-service.sh restart`.

---

## 1. Что такое SPECTRA и его возможности

SPECTRA — это прокси-протокол нового поколения для обхода цензуры и DPI (Deep Packet Inspection). Он туннелирует произвольный TCP-трафик внутри QUIC-потоков, которые статистически неотличимы от трафика облачного гейминга (GeForce NOW).

Текущая релизная база: `0.1.4`

### Ключевые возможности

- **Камуфляж под облачный гейминг** — трафик имитирует NVIDIA GeForce NOW по размерам пакетов и временным интервалам между ними
- **Шифрование XChaCha20-Poly1305** — AEAD-шифрование с ключами, выведенными через HKDF
- **Устойчивость к активному зондированию** — при попытке подключения без правильного PSK сервер отвечает как обычный веб-сервер (decoy-страница)
- **Защита от повторных атак (replay)** — фильтр Блума + временное окно не дают переиспользовать перехваченные хендшейки
- **Формирование трафика (traffic shaping)** — цепь Маркова управляет расписанием отправки пакетов, имитируя реальные паттерны гейминга
- **SOCKS5-интерфейс** — стандартный SOCKS5-прокси на клиентской стороне, совместим с любыми приложениями
- **Мультиплексирование** — множество TCP-соединений через одно QUIC-соединение
- **Padding в idle** — даже в простое генерируются зашифрованные пакеты, неотличимые от реальных данных
- **Auto-reconnect** — при обрыве соединения клиент автоматически переподключается с exponential backoff
- **Graceful drain** — при штатной остановке все активные соединения корректно завершаются

### Как это работает (схема)

```
┌─────────────────┐       QUIC/TLS 1.3 (UDP:443)       ┌─────────────────┐
│  Ваш компьютер  │◄══════════════════════════════════►│   VPS-сервер    │
│                 │   (выглядит как облачный гейминг)   │                 │
│  SOCKS5 :1080   │                                     │  TCP → Интернет │
└────────┬────────┘                                     └────────┬────────┘
         │                                                       │
    Браузер/Apps                                          Целевые сайты
```

---

## 2. Требования

### Для сервера (VPS/VDS)
- **ОС**: Ubuntu 20.04+ / Debian 11+ / любой Linux
- **Go**: версия 1.22+ (инструкция по установке ниже)
- **Домен**: собственный домен с DNS A-записью, указывающей на IP сервера
- **TLS-сертификат**: Let's Encrypt (бесплатно) или другой
- **Порты**: UDP 443 должен быть открыт в фаерволе
- **RAM**: минимум 512 МБ
- **CPU**: 1 vCPU достаточно для ~100 Мбит/с трафика

### Для клиента (Ubuntu Desktop)
- **ОС**: Ubuntu 20.04+ или любой Linux
- **Go**: версия 1.22+ (для сборки из исходников)
- **Сеть**: доступ к серверу по UDP:443

---

## 3. Быстрый деплой одной командой (рекомендуется)

В проекте есть готовые скрипты, которые автоматизируют весь процесс: установку Go, сборку, генерацию ключей, настройку systemd, тюнинг сети и открытие портов.

### Предварительные требования

1. **Домен** с DNS A-записью, указывающей на IP вашего VPS:
   ```
   gaming.ваш-домен.com  →  <IP-ВАШЕГО-СЕРВЕРА>
   ```

2. **SSL-сертификат** для домена (wildcard или обычный). Если нет — получите через Let's Encrypt:
   ```bash
   ssh root@<IP-ВАШЕГО-СЕРВЕРА>
   sudo apt update && sudo apt install -y certbot
   sudo certbot certonly --standalone -d gaming.ваш-домен.com
   # Сертификаты окажутся в:
   #   /etc/letsencrypt/live/gaming.ваш-домен.com/fullchain.pem
   #   /etc/letsencrypt/live/gaming.ваш-домен.com/privkey.pem
   ```

### Шаг 3.1 — Деплой сервера на VPS

```bash
ssh root@<IP-ВАШЕГО-СЕРВЕРА>

# Клонировать репозиторий
git clone https://github.com/anyagixx/SPECTRA.git /opt/spectra
cd /opt/spectra

# Запустить деплой-скрипт
sudo ./scripts/deploy-server.sh \
  --cert /etc/letsencrypt/live/gaming.ваш-домен.com/fullchain.pem \
  --key  /etc/letsencrypt/live/gaming.ваш-домен.com/privkey.pem
```

**Что делает скрипт автоматически:**
- Устанавливает Go 1.22 (если не установлен)
- Собирает `spectra-server` из исходников
- Генерирует PSK (или принимает `--psk ВАШ_КЛЮЧ`)
- Копирует сертификаты в `/opt/spectra/certs/`
- Применяет sysctl-тюнинг для UDP-буферов
- Создаёт и запускает systemd-сервис `spectra`
- Хранит секреты сервера в `/etc/spectra/spectra.env` с правами `600`, а не в `ExecStart`
- Открывает UDP 443 в фаерволе (ufw/firewalld)

**В конце скрипт выводит:**
```
╔══════════════════════════════════════════════════╗
║            Deployment Complete!                  ║
╚══════════════════════════════════════════════════╝

Server is running. Check status:
  sudo systemctl status spectra
  sudo journalctl -u spectra -f

=== YOUR PSK (save this!) ===
  a1b2c3d4e5f6...   ← СОХРАНИТЕ ЭТО!

=== Ubuntu Desktop client service command ===
  ./scripts/client-service.sh install \
    --server gaming.ваш-домен.com:443 \
    --sni gaming.ваш-домен.com \
    --psk "a1b2c3d4e5f6..."
  ./scripts/quic-tune.sh enable
```

> **Важно:** Скопируйте PSK и команду для клиента — они понадобятся на следующем шаге. Не публикуйте PSK в GitHub, чатах и скриншотах.

#### Дополнительные параметры скрипта

| Параметр | Описание |
|----------|----------|
| `--cert PATH` | **Обязательный.** Путь к TLS-сертификату |
| `--key PATH` | **Обязательный.** Путь к TLS-ключу |
| `--psk HEX` | Свой PSK (64 hex-символа). Если не указан — генерируется автоматически |
| `--domain DOMAIN` | Домен для вывода в клиентской команде (автоопределяется из сертификата) |
| `--listen ADDR` | Адрес прослушивания (по умолчанию `:443`) |
| `--dir PATH` | Путь установки (по умолчанию `/opt/spectra`) |
| `--repo URL` | URL git-репозитория (для remote-деплоя) |

### Шаг 3.2 — Проверка сервера

```bash
# Статус сервиса
sudo systemctl status spectra

# Логи в реальном времени
sudo journalctl -u spectra -f

# Перезапуск
sudo systemctl restart spectra

# Остановка
sudo systemctl stop spectra
```

---

## 4. Запуск клиента на Ubuntu Desktop

### Способ 1 — systemd user-service (рекомендуется)

```bash
# Клонировать репозиторий
git clone https://github.com/anyagixx/SPECTRA.git ~/SPECTRA
cd ~/SPECTRA

# Установить и запустить клиент как user service
./scripts/client-service.sh install \
  --server gaming.ваш-домен.com:443 \
  --sni gaming.ваш-домен.com \
  --psk "a1b2c3d4e5f6..."

# Включить QUIC tuning
./scripts/quic-tune.sh enable
```

Проверка и управление:

```bash
./scripts/client-service.sh status
./scripts/client-service.sh logs
./scripts/client-service.sh restart
./scripts/client-service.sh stop
./scripts/client-service.sh uninstall
```

### Способ 2 — Интерактивный запуск в текущем терминале

```bash
# Клонировать репозиторий
git clone https://github.com/anyagixx/SPECTRA.git ~/spectra
cd ~/spectra

# Запустить клиент
./scripts/run-client.sh
```

Скрипт интерактивно спросит:
```
Enter server address (e.g. gaming.example.com:443):
> gaming.ваш-домен.com:443

Enter PSK (64 hex chars, from server deployment):
> a1b2c3d4e5f6...

SNI domain [gaming.ваш-домен.com]:
> (Enter — принять автоматическое значение)

SOCKS5 listen address [127.0.0.1:1080]:
> (Enter — оставить по умолчанию)
```

**Что делает скрипт автоматически:**
- Устанавливает Go (если не установлен)
- Собирает `spectra-client` (если бинарника нет или он устарел)
- Применяет sysctl-тюнинг для UDP-буферов (если есть sudo)
- Запускает клиент и выводит тест-команды

Можно также передать параметры без интерактивного режима:
```bash
./scripts/run-client.sh \
  --server gaming.ваш-домен.com:443 \
  --psk "a1b2c3d4e5f6..."
```

### Способ 3 — Ручной запуск

```bash
cd ~/spectra

# Установить Go (если не установлен)
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Собрать
go build -o spectra-client ./cmd/spectra-client

# Запустить
./spectra-client \
  --psk "ВСТАВЬТЕ_PSK_С_СЕРВЕРА" \
  --server gaming.ваш-домен.com:443 \
  --sni gaming.ваш-домен.com \
  --socks 127.0.0.1:1080 \
  --profile configs/profiles/geforcenow.json
```

Ожидаемый вывод:
```
[client] SOCKS5 proxy listening on 127.0.0.1:1080
[client] Tunnel established to gaming.ваш-домен.com:443
```

> **Примечание:** При обрыве соединения клиент автоматически переподключается с нарастающей задержкой (1с → 2с → 4с → ... → макс. 30с).

### Шаг 4.1 — Проверка работы

В другом терминале:
```bash
# Показать IP — должен быть IP вашего VPS, а не локальный
curl --socks5 127.0.0.1:1080 https://ifconfig.me

curl --socks5 127.0.0.1:1080 https://httpbin.org/ip

# Тест скорости
curl --socks5 127.0.0.1:1080 -o /dev/null -w "Speed: %{speed_download} bytes/sec\n" https://speed.hetzner.de/100MB.bin
```

### Шаг 4.2 — Тюнинг UDP-буферов (важно для скорости!)

В релизе `0.1.4` не нужно вручную копировать sysctl-файл в `/etc/sysctl.d/`. Используйте helper:

```bash
cd ~/SPECTRA  # или каталог, куда вы клонировали проект
./scripts/quic-tune.sh enable
```

Проверка:
```bash
./scripts/quic-tune.sh status
# Ожидается: 8388608 (8 МБ)
```

Если в логах есть `failed to sufficiently increase receive buffer size` — тюнинг ещё не применён.

Отключить persistent-тюнинг и восстановить сохранённые runtime-значения:

```bash
./scripts/quic-tune.sh disable
```

---

## 5. Ручное развёртывание на VPS (альтернатива)

Этот раздел описывает пошаговый процесс без скриптов. **Если вы уже задеплоили через `deploy-server.sh` (секция 3), пропустите этот раздел.**

### Шаг 5.1 — Подключение и установка Go

```bash
ssh root@<IP-ВАШЕГО-СЕРВЕРА>

wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

### Шаг 5.2 — Домен и сертификат

В панели управления вашего домена создайте A-запись:
```
gaming.ваш-домен.com  →  <IP-ВАШЕГО-СЕРВЕРА>
```

Получите сертификат:
```bash
sudo apt update && sudo apt install -y certbot
sudo certbot certonly --standalone -d gaming.ваш-домен.com
```

### Шаг 5.3 — Сборка и запуск

```bash
git clone https://github.com/anyagixx/SPECTRA.git /opt/spectra
cd /opt/spectra

go build -ldflags="-s -w" -o spectra-server ./cmd/spectra-server

# Генерация PSK
PSK=$(openssl rand -hex 32)
echo "Ваш PSK: $PSK"  # СОХРАНИТЕ!

# Тестовый запуск
sudo ./spectra-server \
  --psk "$PSK" \
  --cert /etc/letsencrypt/live/gaming.ваш-домен.com/fullchain.pem \
  --key /etc/letsencrypt/live/gaming.ваш-домен.com/privkey.pem \
  --listen :443 \
  --profile configs/profiles/geforcenow.json
```

### Шаг 5.4 — Настройка systemd-сервиса

```bash
sudo install -d -m 700 /etc/spectra
sudo tee /etc/spectra/spectra.env > /dev/null <<EOF
SPECTRA_PSK=$PSK
SPECTRA_CERT=/etc/letsencrypt/live/gaming.ваш-домен.com/fullchain.pem
SPECTRA_KEY=/etc/letsencrypt/live/gaming.ваш-домен.com/privkey.pem
SPECTRA_LISTEN=:443
SPECTRA_PROFILE=/opt/spectra/configs/profiles/geforcenow.json
EOF
sudo chmod 600 /etc/spectra/spectra.env

sudo tee /etc/systemd/system/spectra.service > /dev/null <<EOF
[Unit]
Description=SPECTRA Proxy Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/spectra
EnvironmentFile=/etc/spectra/spectra.env
ExecStart=/opt/spectra/spectra-server
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable spectra
sudo systemctl start spectra
sudo systemctl status spectra
```

### Шаг 5.5 — Фаервол и sysctl

```bash
sudo ufw allow 443/udp
sudo install -m 644 deployments/sysctl/99-spectra-quic.conf /etc/sysctl.d/99-spectra-quic.conf
sudo sysctl --system
```

---

## 6. Локальное тестирование (клиент + сервер на одной машине)

Для тестирования без VPS можно запустить оба компонента на одной машине с самоподписанным сертификатом.

### Шаг 6.1 — Создание самоподписанного сертификата

```bash
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes \
  -subj "/CN=localhost"
```

### Шаг 6.2 — Сборка

```bash
cd /путь/к/проекту

go mod tidy
go build -o spectra-server ./cmd/spectra-server
go build -o spectra-client ./cmd/spectra-client
```

### Шаг 6.3 — Генерация PSK

```bash
PSK=$(openssl rand -hex 32)
echo "PSK: $PSK"
```

### Шаг 6.4 — Запуск сервера (терминал 1)

```bash
./spectra-server \
  --psk "$PSK" \
  --cert certs/cert.pem \
  --key certs/key.pem \
  --listen :4443 \
  --profile configs/profiles/geforcenow.json
```

Используем порт 4443 чтобы не требовать root-прав.

### Шаг 6.5 — Запуск клиента (терминал 2)

```bash
./spectra-client \
  --psk "$PSK" \
  --server 127.0.0.1:4443 \
  --sni localhost \
  --socks 127.0.0.1:1080 \
  --insecure \
  --profile configs/profiles/geforcenow.json
```

Флаг `--insecure` нужен для самоподписанного сертификата. **Не используйте его в продакшене!**

### Шаг 6.6 — Тест (терминал 3)

```bash
# Проверка соединения
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip

# Проверка HTTPS
curl --socks5 127.0.0.1:1080 https://example.com
```

### Шаг 6.7 — Запуск unit-тестов

```bash
# Запустить все тесты
go test ./internal/... -v
go test ./... -v
go test -race ./...

# Ожидаемый результат: все тесты PASS
```

---

## 7. Использование через браузер и приложения

### Firefox

1. Откройте **Настройки** → **Основные** → прокрутите вниз до **Параметры сети** → **Настроить...**
2. Выберите **Ручная настройка прокси**
3. В поле **Узел SOCKS** введите: `127.0.0.1`
4. В поле **Порт**: `1080`
5. Выберите **SOCKS v5**
6. Поставьте галочку **Отправлять DNS-запросы через прокси при использовании SOCKS v5**
7. Нажмите **OK**

### Google Chrome / Chromium

```bash
# Запустить Chrome с SOCKS5-прокси
google-chrome --proxy-server="socks5://127.0.0.1:1080"

# Или Chromium
chromium-browser --proxy-server="socks5://127.0.0.1:1080"
```

### Системный прокси (GNOME / Ubuntu Desktop)

```bash
# Через gsettings
gsettings set org.gnome.system.proxy mode 'manual'
gsettings set org.gnome.system.proxy.socks host '127.0.0.1'
gsettings set org.gnome.system.proxy.socks port 1080

# Отключить прокси
gsettings set org.gnome.system.proxy mode 'none'
```

Или через GUI: **Настройки** → **Сеть** → **Прокси** → **Вручную** → SOCKS: `127.0.0.1:1080`

### Командная строка (curl, wget)

```bash
# curl
curl --socks5-hostname 127.0.0.1:1080 https://example.com

# Переменные окружения для всех программ
export ALL_PROXY=socks5://127.0.0.1:1080
export all_proxy=socks5://127.0.0.1:1080
wget https://example.com

# Отменить
unset ALL_PROXY all_proxy
```

### Telegram

1. Откройте **Настройки** → **Данные и память** → **Тип подключения**
2. Выберите **Использовать прокси**
3. **Добавить прокси** → тип: **SOCKS5**
4. Сервер: `127.0.0.1`, Порт: `1080`
5. Логин/пароль: оставить пустыми

> **Важно:** Telegram Desktop может создавать сотни параллельных SOCKS-соединений и обращаться к IPv6-адресам, которые VPS может не маршрутизировать. Сначала проверьте SPECTRA через `curl` или браузер. Если после Telegram прокси перестал отвечать, выполните `./scripts/client-service.sh restart`.

---

## 8. Docker-развёртывание

### Предварительные требования

```bash
# Установка Docker (если не установлен)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Установка Docker Compose
sudo apt install -y docker-compose-plugin
```

### Сервер (Docker)

```bash
cd /root/spectra

# Подготовить сертификаты
mkdir -p deployments/certs
cp /etc/letsencrypt/live/gaming.ваш-домен.com/fullchain.pem deployments/certs/cert.pem
cp /etc/letsencrypt/live/gaming.ваш-домен.com/privkey.pem deployments/certs/key.pem

# Задать переменные окружения
export SPECTRA_PSK="ВСТАВЬТЕ_ВАШ_PSK"

# Запустить
docker compose -f deployments/docker-compose.server.yml up -d

# Проверить логи
docker compose -f deployments/docker-compose.server.yml logs -f
```

### Клиент (Docker)

```bash
cd ~/spectra

export SPECTRA_PSK="ВСТАВЬТЕ_ВАШ_PSK"
export SPECTRA_SERVER="gaming.ваш-домен.com:443"
export SPECTRA_SNI="gaming.ваш-домен.com"

docker compose -f deployments/docker-compose.client.yml up -d

# SOCKS5-прокси будет доступен на localhost:1080
```

### Остановка

```bash
# Сервер
docker compose -f deployments/docker-compose.server.yml down

# Клиент
docker compose -f deployments/docker-compose.client.yml down
```

---

## 9. Параметры конфигурации

### Все параметры (флаги и переменные окружения)

#### Сервер (`spectra-server`)

| Флаг | Переменная окружения | По умолчанию | Описание |
|------|---------------------|-------------|----------|
| `--psk` | `SPECTRA_PSK` | — | **Обязательный.** PSK-ключ (64 hex-символа) |
| `--cert` | `SPECTRA_CERT` | — | **Обязательный.** Путь к TLS-сертификату |
| `--key` | `SPECTRA_KEY` | — | **Обязательный.** Путь к TLS-ключу |
| `--listen` | `SPECTRA_LISTEN` | `:443` | Адрес прослушивания (UDP) |
| `--profile` | `SPECTRA_PROFILE` | `configs/profiles/geforcenow.json` | Профиль трафика |

#### Клиент (`spectra-client`)

| Флаг | Переменная окружения | По умолчанию | Описание |
|------|---------------------|-------------|----------|
| `--psk` | `SPECTRA_PSK` | — | **Обязательный.** PSK-ключ (тот же, что на сервере) |
| `--server` | `SPECTRA_SERVER` | — | **Обязательный.** Адрес сервера (`host:port`) |
| `--sni` | `SPECTRA_SNI` | из `--server` | SNI-имя для TLS (обычно = домену) |
| `--socks` | `SPECTRA_SOCKS_LISTEN` | `127.0.0.1:1080` | Адрес SOCKS5-прокси |
| `--profile` | `SPECTRA_PROFILE` | `configs/profiles/geforcenow.json` | Профиль трафика |
| `--insecure` | — | `false` | Пропустить проверку TLS-сертификата (только для тестов!) |

---

## 10. Устранение неполадок

### Клиент не подключается к серверу

1. **Проверьте, что сервер запущен:**
   ```bash
   sudo systemctl status spectra
   # или
   sudo ss -ulnp | grep 443
   ```

2. **Проверьте фаервол:**
   ```bash
   # На сервере — UDP 443 должен быть открыт
   sudo ufw status
   # Если заблокирован:
   sudo ufw allow 443/udp
   ```

3. **Проверьте DNS:**
   ```bash
   dig gaming.ваш-домен.com
   # A-запись должна указывать на IP сервера
   ```

4. **Проверьте доступность порта с клиента:**
   ```bash
   # Проверка UDP-доступности
   nc -zuv gaming.ваш-домен.com 443
   ```

### Ошибка "PSK is required"

Убедитесь, что PSK передаётся правильно:
```bash
# PSK — это 64 hex-символа (32 байта)
# Пример правильного PSK:
# a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
echo -n "$PSK" | wc -c
# Должно быть 64
```

### Ошибка сертификата

```bash
# Проверить сертификат
openssl x509 -in /etc/letsencrypt/live/gaming.ваш-домен.com/fullchain.pem -text -noout | head -20

# Обновить сертификат, если истёк
sudo certbot renew
```

### Медленная скорость

- Если у VPS порт `100 Mbit/s`, реальный потолок полезного трафика обычно будет около `90-95 Mbit/s`, а не `300 Mbit/s`
- На клиенте и сервере обязательно примените `deployments/sysctl/99-spectra-quic.conf`, иначе QUIC останется на маленьких UDP-буферах
- После применения `sysctl` перезапустите `spectra-client` и `spectra-server`
- Если в логах есть `failed to sufficiently increase receive buffer size`, локальная машина всё ещё ограничивает скорость
- Для максимальной скорости располагайте VPS ближе к целевым серверам и к себе по RTT

### Просмотр логов

```bash
# systemd
sudo journalctl -u spectra -f --no-pager

# Docker
docker compose -f deployments/docker-compose.server.yml logs -f
```

---

## 11. Безопасность

### Важные рекомендации

1. **Храните PSK в безопасности** — это единственный секрет, компрометация PSK = компрометация всего туннеля
2. **Используйте реальный TLS-сертификат** в продакшене (Let's Encrypt), никогда `--insecure`
3. **Выбирайте правдоподобный домен** — например, `gaming.example.com`, `play.example.com`, `cloud.example.com`
4. **Регулярно обновляйте PSK** — генерируйте новый ключ периодически
5. **Не запускайте от root** в продакшене — создайте отдельного пользователя (для портов < 1024 используйте `setcap`)

### Запуск без root (рекомендуется)

```bash
# Создать пользователя
sudo useradd -r -s /bin/false spectra

# Разрешить привязку к порту 443 без root
sudo setcap 'cap_net_bind_service=+ep' /opt/spectra/spectra-server

# Скопировать сертификаты в доступную директорию
sudo mkdir -p /opt/spectra/certs
sudo cp /etc/letsencrypt/live/gaming.ваш-домен.com/fullchain.pem /opt/spectra/certs/
sudo cp /etc/letsencrypt/live/gaming.ваш-домен.com/privkey.pem /opt/spectra/certs/
sudo chown -R spectra:spectra /opt/spectra

# Обновить systemd-сервис: User=spectra
```

### Автообновление сертификата

```bash
# certbot автоматически обновляет сертификаты, но нужно перезапустить сервер
sudo tee /etc/letsencrypt/renewal-hooks/post/restart-spectra.sh > /dev/null <<'EOF'
#!/bin/bash
cp /etc/letsencrypt/live/gaming.ваш-домен.com/fullchain.pem /opt/spectra/certs/cert.pem
cp /etc/letsencrypt/live/gaming.ваш-домен.com/privkey.pem /opt/spectra/certs/key.pem
systemctl restart spectra
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/post/restart-spectra.sh
```

---

## Краткая шпаргалка

```bash
# ╔═══════════════════════════════════════════╗
# ║  Вариант 1 — Скрипты (рекомендуется)      ║
# ╚═══════════════════════════════════════════╝

# === На сервере (VPS) ===
git clone https://github.com/anyagixx/SPECTRA.git /opt/spectra
cd /opt/spectra
sudo ./scripts/deploy-server.sh \
  --cert /etc/letsencrypt/live/ДОМЕН/fullchain.pem \
  --key  /etc/letsencrypt/live/ДОМЕН/privkey.pem
# → скрипт выведет PSK и команду для клиента

# === На клиенте (Ubuntu Desktop) ===
git clone https://github.com/anyagixx/SPECTRA.git ~/spectra
cd ~/spectra
./scripts/run-client.sh
# → спросит адрес сервера и PSK, запустит прокси

# ╔═══════════════════════════════════════════╗
# ║  Вариант 2 — Вручную                      ║
# ╚═══════════════════════════════════════════╝

# === На сервере ===
PSK=$(openssl rand -hex 32)
echo "PSK: $PSK"  # СОХРАНИТЕ!
sudo ./spectra-server \
  --psk "$PSK" \
  --cert /etc/letsencrypt/live/ДОМЕН/fullchain.pem \
  --key /etc/letsencrypt/live/ДОМЕН/privkey.pem

# === На клиенте ===
./spectra-client --psk "ВСТАВИТЬ_PSK" --server ДОМЕН:443

# ╔═══════════════════════════════════════════╗
# ║  Проверка и тесты                          ║
# ╚═══════════════════════════════════════════╝

curl --socks5 127.0.0.1:1080 https://ifconfig.me
go test ./internal/... -v
```
