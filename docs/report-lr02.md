# Звіт WEB ЛР 2

## 1. Ідентифікація

- ПІБ і група: Токарчук Влад, група: 43.
- Спільний baseline 2-A; індивідуального номера немає.
- Заявлений рівень: Відмінно.
- Гілка `lab/2-input-sqli`: створена від тегу `v0.1.0`.
- Release, base_commit та entry_parent із квитанції (`.scaffolds/lab-02.json`):
  - `release`: `lab-02-start-v1`
  - `base_commit`: `cf7f58ae4cd37cc5d4c8668b3c155874b7dc21c6`
  - `entry_parent`: `cf7f58ae4cd37cc5d4c8668b3c155874b7dc21c6`
- Vulnerable commit: `ef724347b8de56afa44659ec288994bd3fb94694` («Validate create contract; preserve search evidence»).
- Fixed commit коду: `55177405dfacedb5f28ea3707104029512dc9416`(«Validate incident input and secure search query»).
- Фінальний тег `v0.2.0` на commit із завершеним звітом: `6834d2bc2571026377e461056eb3ee7bb7c4b8fa`
- DEL-01: URL приватного remote з доступом або ім'я переданого bundle: `https://github.com/d9putat1/lab01`.

## 2. Контракт і CP-01

### Реалізовані правила (`POST /api/incidents`, `Lab02Endpoints.cs`)

| Поле | Правило | Відповідь при порушенні |
|---|---|---|
| `title` | обов'язкове після `Trim()`; довжина вхідного значення ≤ 160 | `400`, ключ `title` |
| `description` | обов'язкове після `Trim()`; довжина вхідного значення ≤ 4000 | `400`, ключ `description` |
| `severity` | `Enum.TryParse(ignoreCase: true)` **і** `Enum.IsDefined` — лише `Low/Medium/High/Critical` | `400`, ключ `severity` |
| `occurredAtUtc` | обов'язкове; не пізніше `now.AddMinutes(5)` | `400`, ключ `occurredAtUtc` |
| `occurredAtUtc` (T-10, власне правило) | не раніше `now.AddDays(-365)` | `400`, ключ `occurredAtUtc` |
| cross-field | `severity ∈ {High, Critical}` → `description.Trim().Length ≥ 40` | `400`, ключ `description` |
| предметний конфлікт | той самий `title` (після `Trim()`, з урахуванням регістру) серед статусів `New/Triaged/InProgress/Resolved` | `409 Conflict` |

Нормалізація (`Trim()`) виконується **один раз** після збору помилок базових полів; значення з контракту (`title`, `description`, перевірений `severity`, UTC-нормалізована `occurredAtUtc`) використовуються і для перевірки конфлікту, і для запису в сутність. Усі помилки збираються в `Dictionary<string, string[]>` і повертаються одним `Results.ValidationProblem(errors)` **до** будь-якого звернення до бази даних.

### Server-managed поля і захист від overposting

`CreateIncidentRequest` містить лише 4 поля: `Title`, `Description`, `Severity`, `OccurredAtUtc`. Поля `Id`, `OwnerUserId`, `Status`, `CreatedAtUtc`, `UpdatedAtUtc` клієнт **фізично не може передати** — вони встановлюються сервером безпосередньо в коді створення сутності (`Id = Guid.NewGuid()`, `OwnerUserId = DbSeeder.AliceId`, `Status = IncidentStatus.New`, часи — з `DateTimeOffset.UtcNow`, зафіксованого на початку обробки запиту).

### Response-контракт

Окремий `CreatedIncidentResponse` (7 полів: Id, Title, Description, Severity, Status, OccurredAtUtc, CreatedAtUtc) — не серіалізує сутність `Incident` напряму.

### Підтверджено (CP-01)

- T-01 (коректне створення) → `201`, тіло відповідає `CreatedIncidentResponse`.
- T-02 (invalid severity `"7"`, відсутня `occurredAtUtc`, дата в майбутньому) → `400`, відповідний ключ у `errors`.
- T-09 (межа cross-field 39/40 символів) → `400` / `201` відповідно.
- T-03 (повторний активний `title`) → `201` на першому, `409` на другому створенні.
- Overposting-проба (зайві `id`/`ownerUserId`/`status` у тілі) → `201` з **новим** `id`, `status: "New"` — підтверджено й окремим автотестом `Post_WithOverpostingFields_ServerAssignsOwnStatusAndId`.

## 3. Security-сценарій і CP-02/CP-03

### Контекст і гіпотеза

Endpoint `GET /api/incidents/search` (сканфолд, до виправлення) формував SQL-команду через рядкову конкатенацію параметра `q` і `order` (похідного від `sortBy`), після чого виконував її через `FromSqlRaw`. Гіпотеза: недовірене значення `q` здатне вплинути на структуру SQL-команди.

### Стан до виправлення (vulnerable commit `ef72434`)

Код (`Lab02Endpoints.cs`, метод `MapLab02Endpoints`):
```
var sql = "SELECT * FROM incidents WHERE title ILIKE '%" + (q ?? "")
    + "%' OR description ILIKE '%" + (q ?? "") + "%' ORDER BY " + order + " LIMIT 50";
var rows = await db.Incidents.FromSqlRaw(sql).AsNoTracking().ToListAsync(ct);
```

### Мінімальний локальний PoC (read-only, лише власний стенд)

| Запит | `q` (декодовано) | Статус | Спостереження |
|---|---|---|---|
| A | `USB` | 200 | 1 запис (контрольний, відомий результат) |
| B | `zz-no-match` | 200 | `[]` (значення, якого свідомо немає) |
| S-01 | `zz-no-match' OR TRUE -- ` | **200** | **усі записи таблиці** (5 на чистому seed) — замість очікуваного `[]` |
| D | `O'Brien` | **500** | синтаксична помилка PostgreSQL (легітимний апостроф) |

### Першопричина

`src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`, метод `MapLab02Endpoints`, рядки формування `sql` (наведено вище): значення `q` і `order` конкатенуються в текст SQL-команди до виконання. У журналі EF Core це видно за `Parameters=[]` (порожньо) — жодне значення не передане окремо від тексту команди.

### Виправлення (fixed, Lab02Endpoints.cs)

Перехід на LINQ + `EF.Functions.ILike` із явним escape-символом (literal substring) і allowlist для сортування:
```
var pattern = "%" + EscapeLike(q ?? "") + "%";
var found = db.Incidents.AsNoTracking()
    .Where(incident =>
        EF.Functions.ILike(incident.Title, pattern, "\\")
        || EF.Functions.ILike(incident.Description, pattern, "\\"));

IQueryable<Incident>? ordered = sortBy switch
{
    null or "" or "createdAtUtc" => found.OrderByDescending(i => i.CreatedAtUtc).ThenBy(i => i.Id),
    "severity" => found.OrderBy(i => /* ранг severity */ 0).ThenBy(i => i.Id),
    "status" => found.OrderBy(i => /* ранг status */ 0).ThenBy(i => i.Id),
    _ => null
};
if (ordered is null) return Results.ValidationProblem(/* ["sortBy"] = [...] */);
```
`EscapeLike` екранує `\`, `_`, `%` (у цьому порядку) перед додаванням зовнішніх `%`. Значення `q` передається в СУБД як параметр (`@pattern`/`@pattern0`), а не як частина тексту команди. `sortBy` — allowlist через `switch`; будь-яке незадеклароване значення повертає `null` → `400` до доступу до БД.

### Повторний і позитивний сценарії (S-02, T-04) — CP-03

| Запит | Статус після виправлення | Спостереження |
|---|---|---|
| A (USB) | 200 | той самий 1 запис — позитивна регресія не зламана |
| S-02 (контрольний payload) | **200** | **`[]`** (було — усі 5 записів) |
| D / T-04 (апостроф `O'Brien`) | **200** | запис «O'Brien classroom report» (було — 500) |
| T-05 (`sortBy=price`) | 400 | ключ `sortBy`, допустимі значення в повідомленні |

У журналі EF Core після виправлення: `Parameters=[@pattern='%USB%', @pattern0='%USB%']` — значення передається окремо від тексту SQL; текст команди містить `ILIKE @pattern ESCAPE '\'`.

Автоматична регресія: `Search_WithSqliControlInput_ReturnsEmptySet` (точна перевірка `Assert.Empty`, не просто "не впало") та `Search_WithUsbQuery_ReturnsExactlyOneKnownRecord` (позитивний контроль поруч).

### Залишковий ризик

Не виявлено. Повний текст SQL, вивід `psql`, connection string і внутрішні деталі винятків у цей звіт і докази **не включені**.

## 4. Фактичні перевірки DEL-02

| ID | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|
| T-01 | Коректне створення інциденту | чистий seed | `POST /api/incidents` з валідним тілом | `201 Created`, `CreatedIncidentResponse` | 201, відповідь з новим `id` | `evidence/t01-response.txt` |
| T-02 | Некоректний DTO (severity `"7"`) | чистий seed | `POST /api/incidents`, `severity: "7"` | `400`, ключ `severity` | 400, `errors.severity` присутній | `evidence/t02-severity-response.txt` |
| T-02 | Некоректний DTO (без `occurredAtUtc`) | чистий seed | `POST /api/incidents` без поля | `400`, ключ `occurredAtUtc` | 400, `errors.occurredAtUtc` присутній | `evidence/t02-missing-date-response.txt` |
| T-02 | Некоректний DTO (дата в майбутньому) | чистий seed | `occurredAtUtc: 2099-...` | `400`, ключ `occurredAtUtc` | 400, збіглось | `evidence/t02-future-date-response.txt` |
| T-03 | Предметний конфлікт (409) | чистий seed | два `POST` з однаковим `title` | 1-й `201`, 2-й `409` | збіглось | `evidence/t03-responses.txt` |
| T-04 | Позитивна регресія пошуку | fixed commit | `q=USB`, `q=O'Brien` | `200` обидва | 200/200, збіглось | `evidence/t04-responses.txt` |
| T-05 | Невідомий `sortBy` | fixed commit | `sortBy=price` | `400`, ключ `sortBy` | 400, збіглось | `evidence/t05-response.txt` |
| T-06 | Ресурс не знайдено | чистий seed | `GET /api/incidents/{неіснуючий id}` | `404 Problem Details` | 404, збіглось | `evidence/t06-response.txt` |
| T-09 | Межа cross-field (39/40 символів) | severity=High | description 39 симв. / 40 симв. | `400` / `201` | 400/201, збіглось | `evidence/t09-responses.txt` |
| T-10 | Власне правило: дата старіша 365 днів | чистий seed | `occurredAtUtc` 2020 рік / 364 дні тому | `400` / `201` | 400/201, збіглось | `evidence/t10-responses.txt` |
| S-01 | Контрольний SQLi-ввід, vulnerable commit | `ef72434` | `q=zz-no-match' OR TRUE -- ` | небажане розширення вибірки | **200, усі 5 записів** замість `[]` | `evidence/s01-vulnerable-response.txt` |
| S-02 | Retest того самого вводу, fixed commit | після виправлення | той самий запит | `200` з `[]` | 200, `[]`, збіглось; автотест `Search_WithSqliControlInput_ReturnsEmptySet` | `evidence/s02-fixed-response.txt` |
| A-01 | Огляд data-access points | — | `git grep FromSqlRaw/ExecuteSqlRaw/"ORDER BY"` + ручний перегляд LINQ-методів | лише довірений raw SQL (TRUNCATE) | підтверджено, таблиця нижче | розділ A-01 |
| A-02 | Overposting / mass-assignment ризик | — | автотест з надісланими `id`/`ownerUserId`/`status` | сервер ігнорує, встановлює власні | підтверджено, `Post_WithOverpostingFields_...` зелений | `evidence/a02-test-output.txt` |

### A-01: Огляд data-access points

| Файл:метод | Категорія звернення до БД | Висновок |
|---|---|---|
| `Lab02Endpoints.cs`, пошук (`MapGet /search`) | LINQ, значення через `@pattern`/`@pattern0` | безпечно — значення не входить у текст SQL; сортування через allowlist |
| `Lab02Endpoints.cs`, створення (`MapPost /incidents`) | LINQ (`AnyAsync` для перевірки дубліката `title`) | безпечно — `title` передається як параметр лямбда-виразу |
| `DatabaseBootstrap.cs`, `InitializeAsync` | `ExecuteSqlRawAsync` зі статичним SQL (`TRUNCATE ... RESTART IDENTITY CASCADE`) | безпечно — текст константний, не збирається з недовірених даних |
| `IncidentQueries.cs`, `GetListAsync` | LINQ (`Where`, `OrderByDescending`) | безпечно — значення через параметри виразів |
| `IncidentQueries.cs`, `GetDetailsAsync` | LINQ (`Where` за `id`) | безпечно — `id` як параметр |
| `IncidentQueries.cs`, `GetSeveritySummaryAsync` | LINQ (`GroupBy`, `Where` за `status`) | безпечно — `status` як параметр |

Build/baseline-tests після останньої зміни: `dotnet build` — 0 Error(s); `dotnet test` — Passed: 14, Failed: 0, Skipped: 0.

## 5. Обмеження і висновок

**Обмеження**: перевірка предметного конфлікту (`AnyAsync` у кроці перед `SaveChangesAsync`) не гарантує інваріант за умови **паралельних** запитів із однаковим `title` — між перевіркою й записом є вікно, у якому два одночасні запити теоретично можуть обидва пройти перевірку `AnyAsync` і створити два активні записи з однаковим `title`. У реальній системі це вимагало б або унікального індексу з частковою умовою (`WHERE status <> 'Closed'`) на рівні БД, або транзакції з відповідним рівнем ізоляції. У межах цієї роботи це свідомо залишено поза обсягом (баз даних constraint не додавався, щоб не виходити за дозволені зміни схеми).

**Висновок**: реалізовано серверну валідацію контракту створення інциденту (required-поля, довжини, enum, дата/UTC, cross-field, предметний конфлікт, власне правило T-10) та усунуто SQL injection у пошуку через перехід від рядкової конкатенації (`FromSqlRaw`) до параметризованого LINQ-запиту (`EF.Functions.ILike` з explicit escape-символом) і allowlist для динамічного сортування. Першопричину підтверджено контрольованим локальним read-only сценарієм (S-01: небажане розширення вибірки з 1 до 5 записів), виправлення підтверджено повторним виконанням того самого вводу (S-02: 200 з `[]`) і позитивною регресією (звичайний пошук і легітимний апостроф продовжують працювати). Додатково виявлено й підтверджено захист від mass-assignment (overposting): контракт `CreateIncidentRequest` структурно не дозволяє клієнту передати server-managed поля.

## 6. Декларація використання ШІ

| Сервіс | Задачі | Авторська адаптація/інтерпретація | Фактична перевірка |
|---|---|---|---|
| Claude (Anthropic) | Пояснення механізму SQL injection і параметризації; допомога у формулюванні серверної валідації контракту за заданими правилами 2-A; допомога в структуруванні автотестів і звіту | Усі запропоновані фрагменти коду адаптовано під фактичні назви типів (`IncidentStatus`, `IncidentSeverity`) та структуру проєкту; контрольні SQLi-сценарії виконано особисто на власному локальному стенді, а не прийнято на віру | Кожен запропонований сценарій (S-01, S-02, T-01–T-10, A-01, A-02) особисto виконано через `.http`-файл або `dotnet test` на власному запуску; результати, наведені в розділі 4, відповідають фактично спостереженим |

## 7. Передавання

- Remote доступний викладачеві або bundle перевірено через verify/list-heads: `⟨виконай git push, перевір на GitHub; або git bundle verify/list-heads, якщо remote немає⟩`.
- У Moodle файли/докази видимі й роботу надіслано: `⟨TODO після здачі⟩`.
- Git diff та історію перевірено на секрети: `⟨виконай git log --all -p -- infra/.env — має бути порожньо; перевір git diff vulnerable..fixed на відсутність connection string/паролів⟩`.