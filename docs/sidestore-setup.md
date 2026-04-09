# Установка CavadVPN на iPhone через SideStore

## Что нужно

- iPhone с iOS 16+
- Компьютер (Windows/Mac) для первоначальной установки SideStore
- Apple ID (бесплатный)
- VPN сервер с настроенным Anisette

## Шаг 1: Установка Anisette-сервера

На Windows Server где работает VPN:

```powershell
# Запустите от администратора
.\scripts\install_anisette.ps1
```

Скрипт:
1. Проверит Apple Music / iTunes
2. Настроит Anisette-сервер на порту 6969
3. Выведет URL: `http://YOUR_SERVER_IP:6969`

## Шаг 2: Установка SideStore на iPhone

### Способ A: через компьютер (рекомендуется)

1. Скачайте **SideStore.ipa** с [sidestore.io](https://sidestore.io)
2. Установите **AltServer** на компьютер
3. Подключите iPhone по USB
4. В AltServer: Install → выберите SideStore.ipa
5. На iPhone: Настройки → Основные → Управление устройством → Доверять

### Способ B: через SideServer-Windows

1. Скачайте SideServer для Windows
2. Подключите iPhone по USB
3. Установите SideStore через SideServer

## Шаг 3: Настройка SideStore

На iPhone откройте **SideStore**:

1. Войдите с вашим Apple ID
2. Перейдите в **Settings** (Настройки)
3. Найдите **Custom Anisette Server URL**
4. Введите: `http://YOUR_SERVER_IP:6969`
5. Сохраните

## Шаг 4: Установка CavadVPN

### Из GitHub Actions

1. Зайдите в ваш GitHub репозиторий → Actions
2. Найдите workflow **"Build iOS IPA (SideStore)"**
3. Скачайте артефакт **CavadVPN-iOS** (содержит .ipa)
4. Передайте IPA файл на iPhone (AirDrop, iCloud, Telegram)
5. Откройте IPA в SideStore → Install

### Через SideStore Source (автообновления)

1. Разместите `sidestore-source.json` на вашем сервере
2. Обновите `downloadURL` и `sourceURL` в JSON
3. В SideStore → Sources → Add Source → введите URL

## Шаг 5: Настройка VPN

После установки CavadVPN на iPhone:

1. Откройте приложение
2. Введите адрес сервера: `YOUR_SERVER_IP:38947`
3. Введите публичный ключ сервера
4. Подключитесь

## Автообновление (раз в 7 дней)

SideStore автоматически переподписывает приложение каждые 7 дней.
Для этого нужно:

- iPhone подключён к WiFi
- SideStore запущен в фоне
- Anisette-сервер работает
- VPN туннель НЕ блокирует Apple серверы (уже настроено: bypass 17.0.0.0/8)

### Если VPN мешает обновлению

CavadVPN автоматически пропускает трафик к Apple серверам мимо VPN.
Если всё равно не работает:

1. Откройте CavadVPN → отправьте команду `pause`
2. Туннель замрёт на 30 секунд
3. SideStore успеет обновить подпись
4. Туннель автоматически возобновится

## Управление Anisette-сервером

```powershell
# Статус
Get-ScheduledTask -TaskName CavadVPN_Anisette

# Остановить
Stop-ScheduledTask -TaskName CavadVPN_Anisette

# Запустить
Start-ScheduledTask -TaskName CavadVPN_Anisette

# Удалить
.\scripts\install_anisette.ps1 -Uninstall
```

## Устранение проблем

### SideStore не может обновить приложение
- Проверьте что Anisette-сервер запущен
- Проверьте что порт 6969 открыт в фаерволе
- Убедитесь что iPhone и сервер в одной сети (или сервер доступен из интернета)

### CavadVPN не подключается
- Проверьте адрес сервера и порт
- Проверьте что VPN сервер запущен
- Попробуйте переустановить приложение

### Приложение перестало работать через 7 дней
- Откройте SideStore → обновите CavadVPN
- Если SideStore тоже не работает → переустановите через компьютер
