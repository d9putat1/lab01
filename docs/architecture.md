# Карта архітектури

Це початкова карта. Під час ЛР 1 доповніть її власним трасуванням запиту,
конкретними файлами та спостереженнями з DevTools і журналу PostgreSQL.

## Компоненти

| Компонент | Розташування | Відповідальність |
|---|---|---|
| Browser client | `src/SecureLab.Api/Client/` | Надсилає HTTP-запити, безпечно показує відповідь через DOM API |
| Presentation | `Presentation/` | Описує endpoints, читає зовнішні параметри, формує HTTP-відповідь |
| Application | `Application/` | Виконує сценарій отримання списку або деталей інциденту |
| Data | `Data/` | Відображає C#-сутності на PostgreSQL через EF Core/Npgsql |
| PostgreSQL | `infra/compose.yaml` | Зберігає навчальні дані у локальному контейнері |

## Підготовлений наскрізний маршрут

```text
submit/click у Client/app.js
  → GET /api/incidents або GET /api/incidents/{id}
  → Presentation/Endpoints/IncidentEndpoints.cs
  → Application/Incidents/IncidentQueries.cs
  → Data/SecureLabDbContext.cs
  → PostgreSQL
  → response DTO у Presentation/Contracts/
  → JSON
  → textContent/createTextNode у Client/app.js
```

## Межі довіри


Користувач → Browser client	Користувач керує вмістом полів вводу і вибором у <select> (напр. значення статусу у формі фільтра); ці елементи не є перевіркою	Клієнтський HTML лише пропонує варіанти вибору — реальна перевірка відбувається пізніше, на сервері

Browser client → API	Клієнт і сам HTTP-запит можна змінити поза UI (наприклад, викликати fetch("/api/incidents/severity-summary?status=Unknown") напряму з консолі браузера, оминаючи форму)	Сервер: Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate) + Enum.IsDefined(candidate) у IncidentEndpoints.GetSeveritySummaryAsync і GetListAsync; повертає 400 Validation Problem Details при некоректному значенні

API → PostgreSQL	Значення status/id, що надійшли від клієнта, не можна підставляти в SQL напряму — це недовірені дані на момент, коли вони перетинають цю межу	EF Core LINQ-запити (Where, GroupBy) параметризують значення автоматично на рівні провайдера Npgsql, без конкатенації рядків; AsNoTracking() явно позначає сценарій лише читання

PostgreSQL → API → DOM	Текст у БД (напр. description seed-інциденту «Перевірка журналу комп'ютерного класу») міг бути раніше введений користувачем і містити <script> — сам факт, що дані вже в БД, не робить їх безпечним HTML	Окремий response DTO (IncidentSeveritySummaryResponse, IncidentDetailsResponse) обмежує, які поля взагалі йдуть назовні; вивід у app.js — виключно через textContent/document.createTextNode/createElement, без innerHTML (перевіряється тестом ClientScript_DoesNotUseDangerousInnerHtmlSink)

API → браузер (право на дані)	Право прочитати список інцидентів не означає право отримати всі поля entity (напр. OwnerUserId, email власника)	Явна проєкція в IncidentDetailsResponse/IncidentSeveritySummaryResponse — повертаються лише перелічені поля, entity Incident назовні не серіалізується напряму

## Конфігураційні входи

global.json — версія .NET SDK (10.0.302, rollForward: latestPatch, смуга 10.0.3xx);

src/SecureLab.Api/appsettings*.json — режим міграцій (Database:ApplyMigrationsOnStartup), дозвіл на reset (Database:AllowReset) і локальний connection string (лише для appsettings.Development.json, прив'язаний до 127.0.0.1);

infra/compose.yaml — версія образу PostgreSQL, порт-мапінг, healthcheck, локальні навчальні облікові дані (securelab / local-study-password);

infra/.env.example / infra/.env — значення POSTGRES_PORT, що читає Docker Compose через --env-file; .env у .gitignore, у репозиторій не потрапляє;

змінна середовища ConnectionStrings__SecureLab — безпечний спосіб перевизначити connection string поза репозиторієм і поза файлами конфігурації; має найвищий пріоритет серед перелічених джерел (стандартний порядок читання конфігурації в ASP.NET Core: appsettings.json → appsettings.{Environment}.json → змінні середовища).

## Змінений маршрут (ЛР 1)

кнопка "Показати підсумок" у Client/index.html
 → loadSeveritySummary у Client/app.js
 → GET /api/incidents/severity-summary?status=...
 → IncidentEndpoints.GetSeveritySummaryAsync (валідація status)
 → IncidentQueries.GetSeveritySummaryAsync
 → SecureLabDbContext.Incidents / таблиця incidents
 → IncidentSeveritySummaryResponse як JSON (4 елементи, повний перелік severity)
 → renderSeveritySummary → textContent у списку

## Залежності конфігурації

| Джерело | Що містить | Звідки береться під час запуску |
|---|---|---|
| `global.json` | вимога до .NET SDK (10.0.302, latestPatch) | читається `dotnet` автоматично в корені `starter-project` |
| `appsettings.Development.json` | `ConnectionStrings:SecureLab`, `Database:ApplyMigrationsOnStartup`, `Database:AllowReset` | завантажується ASP.NET Core в Development environment |
| `infra/.env.example` / `infra/.env` | `POSTGRES_PORT` | читається Docker Compose через `--env-file` |
| `infra/compose.yaml` | опис контейнера PostgreSQL, healthcheck, порт-мапінг | `docker compose up` |
| Змінна середовища `ConnectionStrings__SecureLab` | перевизначає connection string без редагування файлів | найвищий пріоритет серед джерел конфігурації .NET |