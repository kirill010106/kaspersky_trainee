# Safeboard

REST-сервис для хранения сведений об угрозах по MD5 файла. Он хранит метаданные, но не принимает файлы, не вычисляет хеши и не выполняет антивирусный анализ.

## Что реализовано

- `POST /api/v1/info` создаёт запись; повторный MD5 возвращает `409`.
- `GET /api/v1/info/{md5}` читает запись; `PUT /api/v1/info/{md5}` полностью заменяет её редактируемые поля. Отсутствующая запись возвращает `404`.
- `/livez` проверяет HTTP-процесс, `/readyz` — доступ к ожидаемой схеме PostgreSQL. Обе пробы доступны без ключа.
- HTTPS завершается в Go-сервисе. Reader-ключ разрешает GET, writer-ключ — GET, POST и PUT. Для зарегистрированных маршрутов API и `/readyz` действуют независимые лимиты по IP, по умолчанию по 120 запросов в минуту. `/livez` не лимитируется.
- Миграции запускаются отдельной командой `migrate` того же бинарника до запуска `serve`; автоматически при старте API схема не меняется. Поддерживается только применение миграций Up.

Роутер применяет ограничение тела 32 КиБ, OpenAPI-валидацию и строгий разбор JSON. Ответы содержат `X-Request-ID` и `Cache-Control: no-store`; структурированный access log использует тот же ID и не записывает ключи или тела запросов. Формат API описан в [OpenAPI](api/openapi.yaml).

## Быстрый запуск через Docker Compose

Нужны Docker с Compose, OpenSSL и свободный локальный порт `8443`. Команды ниже предназначены для PowerShell и выполняются из корня репозитория. Создайте локальные секреты; `.env`, `*.key` и `*.pem` исключены из Git:

```powershell
if (Test-Path .env) { throw ".env already exists; reuse it for the existing database volume" }
@(
  "POSTGRES_PASSWORD=$((openssl rand -hex 32).Trim())"
  "READER_KEY=$((openssl rand -hex 32).Trim())"
  "WRITER_KEY=$((openssl rand -hex 32).Trim())"
) | Set-Content .env

New-Item -ItemType Directory -Force .local | Out-Null
openssl req -x509 -newkey rsa:2048 -sha256 -noenc -days 7 `
  -keyout .local/safeboard.key -out .local/safeboard.pem `
  -subj "/CN=localhost" `
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Если `.env` уже существует, пропустите его создание: смена пароля в файле не меняет пароль PostgreSQL в существующем томе. Если OpenSSL в Windows не находит `openssl.cnf`, задайте `OPENSSL_CONF` путём к конфигурации своей установки OpenSSL и повторите команду выпуска сертификата. Не добавляйте локальный ключ в репозиторий. Сертификат служит только для локальной проверки; клиент должен явно доверять ему.

```powershell
docker compose config -q
docker compose up --build -d
docker compose ps -a
```

Ожидаемое состояние: `db` — healthy, `migrate` — `Exited (0)`, `api` — Up. API опубликован только на `127.0.0.1:8443`; PostgreSQL доступен лишь внутри сети Compose. Проверка сертификата и проб:

```powershell
curl.exe --noproxy "*" --cacert .local/safeboard.pem `
  --resolve localhost:8443:127.0.0.1 -i https://localhost:8443/livez
curl.exe --noproxy "*" --cacert .local/safeboard.pem `
  --resolve localhost:8443:127.0.0.1 -i https://localhost:8443/readyz
```

Обе команды должны вернуть `200`. Для просмотра логов: `docker compose logs --tail=30 api`. `docker compose down` остановит сервисы и сохранит именованный том БД; не используйте `down -v`, если данные нужны. После повторного `up` миграции можно запускать снова: goose применяет только новые версии.

### Проверка бизнес-API

В той же сессии PowerShell прочитайте ключи локально, не печатая их:

```powershell
$settings = Get-Content .env -Raw | ConvertFrom-StringData
$md5 = (openssl rand -hex 16).Trim()
$createBody = @{
  md5 = $md5
  name = "Smoke threat"
  description = "Before update"
  type = "trojan"
  severity = "high"
} | ConvertTo-Json -Compress

$createBody | curl.exe --noproxy "*" --cacert .local/safeboard.pem `
  --resolve localhost:8443:127.0.0.1 -sS -i -X POST `
  -H "Authorization: Bearer $($settings.WRITER_KEY)" `
  -H "Content-Type: application/json" --data-binary "@-" `
  https://localhost:8443/api/v1/info

curl.exe --noproxy "*" --cacert .local/safeboard.pem `
  --resolve localhost:8443:127.0.0.1 -sS -i `
  -H "Authorization: Bearer $($settings.READER_KEY)" `
  "https://localhost:8443/api/v1/info/$md5"
```

POST должен вернуть `201` и `Location`, GET — `200` с тем же MD5. Для PUT передайте `name`, `type`, `severity` на путь `/api/v1/info/$md5` с writer-ключом; пропущенный `description` станет пустой строкой.

## Контракт данных

| Поле | Правило |
| --- | --- |
| `md5` | Ровно 32 ASCII hex-символа; любой регистр на входе, lowercase в ответе и БД. В POST находится в теле, в GET/PUT — в пути; в теле PUT запрещён |
| `name` | Обязателен при POST/PUT, 1–200 Unicode-кодовых точек после удаления пробелов по краям |
| `description` | Необязателен, до 4096 Unicode-кодовых точек; пропуск при PUT очищает значение |
| `type` | Обязателен: `trojan`, `ransomware`, `spyware`, `adware`, `worm`, `other` |
| `severity` | Обязателен: `low`, `medium`, `high`, `critical` |
| `created_at`, `updated_at` | Назначаются сервером; PUT сохраняет `created_at` |

POST и PUT принимают один JSON-объект с `Content-Type: application/json`, размером до 32768 байт. `null`, неизвестные и повторные поля, неверный регистр имён, плохой UTF-8 и несколько JSON-значений отклоняются. Ошибка возвращается в JSON с обязательным `message` и необязательным `details`. MD5 служит ключом поиска из задания, а не механизмом криптографической защиты.

## Ручной запуск Go

Нужны Go 1.27.1, доступный PostgreSQL 16 с базой `safeboard` и свободный HTTPS-адрес. Переменные `DATABASE_URL`, `TLS_CERT_FILE`, `TLS_KEY_FILE`, `READER_KEY`, `WRITER_KEY` и `HTTPS_ADDR` обязательны для `serve`; `migrate` требует только `DATABASE_URL`. Go не загружает `.env` автоматически. Пример для PostgreSQL, опубликованного локально на `127.0.0.1:55432`:

```powershell
$settings = Get-Content .env -Raw | ConvertFrom-StringData
$env:DATABASE_URL = "postgres://safeboard:$($settings.POSTGRES_PASSWORD)@127.0.0.1:55432/safeboard?sslmode=disable"
go run ./cmd/service migrate

$env:TLS_CERT_FILE = (Resolve-Path .local/safeboard.pem).Path
$env:TLS_KEY_FILE = (Resolve-Path .local/safeboard.key).Path
$env:READER_KEY = $settings.READER_KEY
$env:WRITER_KEY = $settings.WRITER_KEY
$env:HTTPS_ADDR = "127.0.0.1:8443"
go run ./cmd/service serve
```

Успешный `migrate` может завершиться без сообщений. Для ручного режима PostgreSQL должен быть опубликован отдельно: стандартный `compose.yaml` не открывает порт БД на хост. Дополнительные настройки с начальными значениями: `DB_QUERY_TIMEOUT=3s`, `READINESS_TIMEOUT=1s`, `SHUTDOWN_TIMEOUT=10s`, `DB_MAX_CONNS=10`, `READ_HEADER_TIMEOUT=3s`, `READ_TIMEOUT=10s`, `WRITE_TIMEOUT=15s`, `IDLE_TIMEOUT=60s`, `MAX_HEADER_BYTES=16384`, `API_RATE_PER_MINUTE=120`, `READINESS_RATE_PER_MINUTE=120`.

## Устройство и проверки

Один Go-модуль и один процесс API: HTTP-адаптер (`internal/httpapi`) → сервис сценариев (`internal/service`) → порт хранилища → PostgreSQL-адаптер (`internal/storage/postgres`). Доменная модель (`internal/domain`) не зависит от транспорта и БД. Зависимости собираются вручную в `cmd/service`; сгенерированные типы и встроенная OpenAPI остаются в `internal/httpapi/generated`.

```powershell
go test -count=1 ./...
go vet ./...
go test -count=1 -tags=integration -timeout=8m ./tests/integration
```

Обычные тесты не требуют Docker. Интеграционные тесты запускают одноразовую PostgreSQL через Testcontainers и проверяют миграции, HTTP-сценарий, конкурентные операции, таймаут хранилища и ответы при закрытом пуле. Тестовый HTTP-сервер не проверяет TLS; работа HTTPS и сохранение данных после перезапуска Compose отдельно проверены локальным smoke-сценарием.

Генератор закреплён в `go.mod` как Go tool dependency. После изменения [OpenAPI](api/openapi.yaml) обновите модели командой:

```powershell
go tool oapi-codegen -config api/oapi-codegen.yaml api/openapi.yaml
```

Повторная генерация и отрицательные случаи TLS проверены локально. GitHub Actions успешно выполнил форматирование, генерацию, vet, unit- и интеграционные тесты с race detector, сборку Go-сервиса и Docker-образа. Штатная остановка API проверена; остановка при зависшем активном запросе отдельно не проверялась. API-квота охватывает весь `/api/v1`, включая 404/405. `/livez` и пути вне этого префикса не лимитируются; локальный Compose публикует порт только на loopback.
