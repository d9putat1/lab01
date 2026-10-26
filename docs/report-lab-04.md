# Звіт ЛР04

## Контекст і межа виконання
- Рівень: відмінний («Відмінно»). Обґрунтування: виконано вимоги достатнього й доброго рівнів (A-01…A-12) та відмінного (A-11 для `search` і `severity-summary`, окремий resource-based handler, обґрунтування видимості, least privilege, охоплення, залишкових ризиків).
- Власний baseline 2-A (Профіль A «Пошук»), base tag `v0.3.0` → `2fc1306fbf3a77c4502f8a775d57b827c1c21006`; гілка `lab/4-authorization`.
- Головна action: `GET /api/incidents/{id}` (details/read). Політика відмов: **404** для ресурсу, якого principal не бачить (відповідь ідентична відповіді для неіснуючого id); **403** — principal ресурс бачить, але права на дію немає; **409** — перехід недопустимий за поточним статусом; **401** — немає автентифікації.
- Маршрути мого рівня: `GET /api/incidents`, `GET /api/incidents/{id}`, `PUT /api/incidents/{id}`, `DELETE /api/incidents/{id}`, `POST /api/incidents/{id}/triage`, `GET /api/incidents/search`, `GET /api/incidents/severity-summary`, `GET /api/incident-comments/{id}`; `POST /api/incidents` успадковано з ЛР 3 без змін.
- ЛР 3 після тегу не виправлялась: окремого commit-а виправлення немає, тег `v0.3.0` не пересувався. 

Рівні накопичувальні; заповнено свій і всі нижчі. Єдиний рядок, не виконаний за вибором, — A-08b (обрано альтернативу A-08a).

## Матриця і server-side рішення
Матриця: `docs/access-matrix.md` (8 колонок, політика відмов, умови словами, least privilege). Зафіксована в коміті C2 `cff86ede3c1afdec9460266ab8421fc360970b70` **до** PoC і до виправлення.

Правила: Reporter — лише власні інциденти (читання й редагування; видалення лише власного зі статусом New); Analyst — читає всі інциденти й internal comments, виконує лише `New → Triaged`, не редагує й не видаляє; Administrator — без опублікованих прав на Incident, тож обходу ownership немає.

Місця в коді:
- Resource-based handler: `Application/Incidents/IncidentAuthorizationHandler.cs` (операції `Read`, `ReadInternalComments`, `Update`, `Delete`, `Triage` з `IncidentOperations`); реєстрація в `Program.cs`.
- Єдине джерело id і «широкої» видимості: `IncidentAccessPolicy` (`TryGetUserId`, `CanReadAll`) — використовують і handler, і query scoping.
- Query scoping: `IncidentQueries.GetListAsync`, `IncidentQueries.GetSeveritySummaryAsync`, `search` у `Scaffolding/Lab02Endpoints.cs` — умова `canReadAll || OwnerUserId == userId` у запиті до сортування, `Take(50)` і `GroupBy`.
- Дозволені DTO: `UpdateIncidentRequest(Title, Description)` — без Status, Severity, OwnerUserId, Role; відповіді `UpdatedIncidentResponse`, `TriageIncidentResponse`, `IncidentDetailsResponse` не містять `OwnerUserId`.
- Server-managed fields: owner (з principal), наступний status (встановлює `TriageAsync`), `UpdatedAtUtc`, запис `IncidentStatusHistory`.

## Вразливий стан і PoC
Vulnerable commit: `239a6709aaf66fabdf2bfd0c2da918f454819eaa` (приватний навчальний репозиторій). Докази «до»: `docs/evidence/lr04-before.md` (записи B-01…B-15, зняті з коду коміту V).

| Дія | Expected (матриця) | Actual (vulnerable) | Доказ |
|---|---|---|---|
| Alice → власний …0001 | allow | ⟦статус⟧ | B-04 |
| **Alice → інцидент Bob …0002** | deny, 404 | ⟦статус і ключові поля Bob⟧ | B-05 |
| Alice PUT/DELETE інциденту Bob …0004 | deny | ⟦статуси; title після PUT; GET після DELETE⟧ | B-11, B-12 |
| Alice (Reporter) triage свого …0003 | deny | ⟦статус; status після⟧ | B-13 |
| Alice PUT власного з forged severity/status/owner | змінюється лише content | ⟦статус; severity/status/owner після⟧ | B-14 |
| Alice → comment-2 і internal comment-3 | deny | ⟦статуси⟧ | B-09, B-10 |
| анонім → details/search/summary | 401 | ⟦статуси⟧ | B-01…B-03 |

Примітка: `role` та `isTransitionAllowed` у forged-запиті ефекту не мали (у vulnerable DTO таких властивостей немає). Група `/api/incidents` у vulnerable-стані не мала `RequireAuthorization()`, тож маршрути були доступні навіть без cookie. Наївні `PUT/DELETE/triage` і child-endpoint створено у vulnerable commit навмисно (локальні штучні дані); у fixed commit замінено захищеними версіями.

## Виправлення та retest
Fixed commit: `⟦hash F2⟧` (на нього вказує тег `v0.4.0`). Проміжні: F1 `8b37a3eb874dfe5d52d2a9fc4528371abc2b2bb7`; E `⟦hash E⟧`.

Ті самі запити до/після: Alice → Bob details: ⟦200 → 404⟧; PUT/DELETE чужого: ⟦204 → 404⟧; triage Reporter: ⟦204 → 403⟧; forged update: ⟦зміна protected state → ігнорується⟧; comment-2 / internal comment: ⟦200 → 404⟧.
Mutation: стан до/після відмови збігається (A-04, A-06, A-08a): ⟦посилання на записи в lr04-after.md⟧.
Read: DTO details не розкриває `OwnerUserId` та email (`GetDetails_DoesNotExposeInternalOwnerFields`).
Узгодженість 404: однакова політика для details, update, delete, triage і child; A-10 — два тести та дві збережені відповіді.
Автоматична перевірка: `dotnet test` → Passed ⟦N⟧, Failed ⟦0⟧, Skipped ⟦S⟧ (⟦дата⟧).

Як читати докази: mutation perimeter — `PUT`, `DELETE`, `POST …/triage`; state assertion — повторне читання й порівняння `title|description|severity|status` до/після; contract test — запит із зайвими полями (A-08a).

## Доказова таблиця
Якщо головна action — mutation, доказ owner/non-owner для details запишіть у стовпці «Доказ» рядка A-03R.

Усі рівні: автоматичні HTTP A-02/A-03, A-03R — test або `.http`. Добрий додає A-01, A-04–A-07, одне з A-08a/A-08b, A-09, A-12; A-10 лише для 404. A-06 і A-07 автоматичні. Відмінний додає A-11 (search і severity-summary); A-06/A-08a/b успадковано. Запишіть фактичні результати; рядки вищого рівня позначте з поясненням.

| ID | Рівень | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|---|
| A-01 | добрий | Анонімний доступ | немає authentication context | protected request | `401`, не HTML redirect | ⟦заповни: фактичний статус анонімних запитів до 5 маршрутів + PUT/DELETE/triage⟧ | `ProtectedRead_Anonymous_Returns401_WithoutRedirect` (5 шляхів, у т.ч. search), `Mutations_Anonymous_Return401_WithoutRedirect`, `lab-04-retest.http` (анонімні запити) |
| A-02 | достатній, обов’язковий | Власний ресурс | Alice має власний seed resource | вибрана головна action: details/read або одна mutation | allow | ⟦Alice → власний …0001: фактичний статус⟧ | `Details_AsOwner_ReturnsOwnIncident`, `Update_AsOwner_Returns200_AndChangesOnlyContent` |
| A-03 | достатній, обов’язковий | Чужий ресурс | Alice, Bob resource | та сама головна action з підміненим id | `403` або `404`; для mutation state без змін | ⟦Alice → Bob …0002: фактичний статус; тіло без полів Bob⟧ | `Details_AsNonOwnerReporter_Returns404_AndDoesNotLeakBobData`; для mutation — стан до/після (`Update_AsNonOwner_Returns404_AndDoesNotChangeResource`) |
| A-03R | достатній, entry-контракт ЛР 5 | Дозволений аналітичний read | Morgan (`Analyst`), ресурс Alice | `GET /api/incidents/{id}` | allow для аналізу; не надає права довільної mutation | ⟦Morgan → details Alice і Bob: статуси; PUT/DELETE Morgan: статуси⟧ | `Details_AsAnalyst_ReturnsIncidentsOfBothReporters`, `Update_AsAnalyst_Returns403_AndDoesNotChangeIncident`, `Delete_AsAnalyst_Returns403_AndIncidentStillExists`; `.http` |
| A-04 | добрий | Чужий ресурс, усі змінювальні дії | Alice, Bob resource | підмінити id в update/delete | deny, state без змін | ⟦Alice PUT/DELETE Bob: статуси; стан Bob до/після⟧ | `Update_AsNonOwner_Returns404_AndDoesNotChangeResource`, `Delete_AsNonOwner_Returns404_AndResourceStillExists`, `Update_AsNonOwner_WithInvalidBody_Returns404_NotValidationError` |
| A-05 | добрий | List | Alice | list | лише дозволена множина | ⟦Alice list: які id; Morgan list: які id⟧ | `List_AsReporter_ContainsOnlyOwnIncidents`, `List_AsAnalyst_ContainsIncidentsOfAllOwners`; SQL-лог у `docs/evidence/lr04-after.md` |
| A-06 | добрий | Вертикальне підвищення привілеїв | звичайний Reporter | privileged transition | deny, status без змін | ⟦Alice triage власного: статус; status до/після⟧ | `Triage_AsReporterOwner_Returns403_AndDoesNotChangeStatus`, `Triage_AsNonOwnerReporter_Returns404_AndDoesNotChangeStatus` |
| A-07 | добрий | Дозволена привілейована дія | роль і контекст за матрицею | transition за матрицею | allow | ⟦Morgan triage New: статус; запис історії⟧ | `Triage_AsAnalyst_MovesNewToTriaged_AndRecordsHistory`, `Triage_AsAnalyst_OnNonNewIncident_Returns409_AndKeepsStatus` |
| A-08a | добрий, альтернатива A-08b | Надлишкове присвоєння (overposting): контракт ігнорує невідоме поле | authenticated user; DTO не містить protected field | forged owner/role/status field у regular update | дозволений content може змінитися, але protected state — ні | ⟦forged ownerUserId/status/severity/role/isTransitionAllowed: статус; що змінилось, що ні⟧ | `Update_WithForgedProtectedFields_IgnoresThem_AndChangesOnlyContent`, `Update_WithForgedSeverity_DoesNotEscalateIncident` |
| A-08b | добрий, альтернатива A-08a | Overposting: контракт відхиляє зайве або заборонене поле | authenticated user; контракт явно відхиляє поле | той самий forged request | `400` або `403` за контрактом; весь protected state без змін | не виконувалось — обрано альтернативу A-08a | — |
| A-09 | добрий | Аудиторська подія (audit event) | denied privileged request | знайти authorization.denied у виводі API | безпечна подія без секретів | ⟦вставити рядок authorization.denied (без секретів) і traceId з тіла 403⟧ | рядок із виводу API + тіло 403 у `docs/evidence/lr04-after.md`; `AuditLogTests` (якщо стабільний) |
| A-10 | добрий, лише політика `404` | Нерозрізнюваність `404` | той самий authenticated client; identifier чужого й identifier неіснуючого ресурсу | виконати два однакові за структурою запити, змінивши лише id | однакові status, `Content-Type` і тіло після вилучення полів кореляції запиту (`traceId`, `requestId`) | ⟦чужий і неіснуючий id: порівняння status, Content-Type, тіла⟧ | `Details_ForeignAndUnknownId_AreIndistinguishable`, `Update_ForeignAndUnknownId_AreIndistinguishable`; дві відповіді в `lr04-after.md` |
| A-11 | відмінний | Власні endpoint-и ЛР 1–2 | Alice; власні endpoint-и з ЛР 1–2 | виконати `severity-summary` і `search` | результат обмежений дозволеною множиною | ⟦Alice search O'Brien і summary: що повернуло до/після; анонім: статус⟧ | `SearchAndSummaryScopingTests` (7 тестів); докази до — `lr04-before.md`, після — `lr04-after.md` |
| A-12 | добрий | Child resource та internal comment | Alice (`Reporter`); прямий id коментаря Morgan до інциденту Bob (comment-2 у seed-identifiers.json) | запросити `GET /api/incident-comments/{id}` і перевірити details-проєкцію для `Reporter` | direct child access — deny за зафіксованою політикою; internal comment не потрапляє у відповідь `Reporter` | ⟦comment-2 і internal comment-3 для Alice; те саме для Morgan: статуси⟧ | `Comment_OfForeignIncident_AsReporter_Returns404`, `InternalComment_AsOwnerReporter_Returns404_AndIsAbsentFromDetails`, `InternalComment_AsAnalyst_IsReadable_AndPresentInDetails` |

## Основний finding і залишковий ризик (усі рівні)
Контекст: details, mutation, child, search і summary приймали id із запиту й не порівнювали його з principal.
Гіпотеза: Alice (Reporter) зі своєю cookie може прочитати й змінити ресурс Bob, підмінивши лише id (horizontal BOLA/IDOR); Reporter може виконати привілейований перехід і змінити protected поля (vertical).
Стан до (`239a6709aaf66fabdf2bfd0c2da918f454819eaa`): ⟦коротко: Alice → Bob 200 з даними Bob; PUT/DELETE чужого проходять; Reporter виконує triage; forged поля змінюють protected state; internal comment читається Reporter⟧.
Першопричина: `IncidentQueries.GetDetailsAsync` (рядок ≈⟦N⟧ у коміті V) відбирає запис лише за `incident.Id == id`; endpoint не питає про право; `UpdateAsync/DeleteAsync/TriageAsync` завантажували ресурс лише за id; vulnerable `UpdateIncidentRequest` містив `Severity`, `Status`, `OwnerUserId`; child шукався за власним id без перевірки parent; група `/api/incidents` і `search` не мали `RequireAuthorization()`.
Fix і DTO: resource-based handler (+ `IncidentAccessPolicy`) для details/update/delete/triage/child; query scoping для list/search/summary; `UpdateIncidentRequest(Title, Description)`; наступний status встановлює сервер; 404 для невидимого ресурсу; audit на гілці відмови triage.
Retest: ті самі запити → 404/403/409 за матрицею; стан без змін після відмови.
Позитивна регресія: власник (Alice → …0001), Bob → власний, Analyst читає всі й виконує New → Triaged, Administrator без обходу, створення інциденту з ЛР 3 працює; ⟦N⟧ тестів зелені.
Залишковий ризик: CSRF для cookie-мутацій — задокументований навчальний борг до ЛР 6; роль у cookie живе до оновлення сесії/security stamp; audit лише в журналі процесу (не tamper-proof).

## Browser flow (усі рівні)
Login на `auth-lab.html` (alice) → `GET /api/me` ⟦200⟧ → головна сторінка показує ⟦3⟧ власні інциденти → власні details відображено (знімок 1: `⟦файл⟧`) → `loadIncidentDetails("20000000-0000-0000-0000-000000000002")` для Bob → у блоці деталей ⟦«Помилка: Інцидент не знайдено»⟧ (знімок 2: `⟦файл⟧`).
HTTP-результат: власний ⟦200⟧, Bob ⟦404⟧. Клієнт відображає значення через `textContent`/`createTextElement`, не `innerHTML`; він лише показує рішення сервера. Значень credentials, cookie та `Set-Cookie` не збережено.

## Добрий рівень: роль, transition, child, audit (також для відмінного)
Transition: дозволений лише Analyst `New → Triaged`; Reporter (навіть власник) → ⟦403⟧, status без змін; повторний triage і triage не-New → ⟦409⟧; next status встановлює `TriageAsync` (клієнт status не передає).
Child: comment-2 (Morgan до інциденту Bob): Alice → ⟦404⟧; internal comment-3 до інциденту Alice: Alice (Reporter-власник) → ⟦404⟧ і відсутній у details; Morgan (Analyst) → ⟦200⟧ після дозволу на Read parent.
Audit: подія `authorization.denied subject=⟦userId⟧ action=incident.triage resource=⟦incidentId⟧ result=denied occurredAtUtc=⟦UTC⟧ traceId=⟦id⟧` пишеться на обох гілках відмови triage; `traceId` збігається з `traceId` у Problem Details відповіді ⟦так/ні + доказ⟧. У події немає пароля, cookie, token, body.

## Відмінний рівень (додатково до всього доброго)
Resource-based handler: `IncidentAuthorizationHandler` приймає суб'єкт, ресурс (`Incident`) і операцію; рішення централізоване. Для множин (list/search/summary) рішення виражене умовою запиту, яку формує те саме `IncidentAccessPolicy`.

A-11 (finding): `GET /api/incidents/search` не вимагав автентифікації й повертав `Description` чужих інцидентів; `severity-summary` рахував агрегати всіх інцидентів. До (`239a6709aaf66fabdf2bfd0c2da918f454819eaa`): ⟦анонім/Alice бачили інцидент Bob …0004; summary Alice = High 1 / Medium 1 / Low 3⟧. Причина: немає `RequireAuthorization()` і немає умови за власником. Fix (`⟦hash F2⟧`): `RequireAuthorization()` + `canReadAll || OwnerUserId == userId` у запиті до сортування/`Take(50)`/`GroupBy`. Retest: ⟦анонім 401; Alice search `O'Brien` → []; summary Medium 1 / Low 2; Morgan — усе; Bob — власний⟧.

A-08a і A-06 підтверджують захист privilege-related полів і вертикальний regression (нові повторні тести не потрібні).

Обґрунтування видимості: чужий ресурс для Reporter/Administrator дає 404, ідентичну відповіді для неіснуючого id (A-10), щоб API не підтверджував існування чужих інцидентів і не давав перебирати ідентифікатори; 403 — лише коли principal ресурс уже бачить.
Least privilege: Reporter — тільки власне; Analyst — читання всього (для аналізу), єдина зміна — New → Triaged, без довільного редагування/видалення; Administrator — без прав на Incident (у baseline 2-A не опубліковано), обходу ownership немає (тести `…AsAdministrator…`).
Охоплення: ⟦вставити таблицю периметра з git grep⟧. Batch/export — не існують у проєкті: не застосовується. Concurrent transitions — викладач сценарій не надав: не застосовується.
Залишкові ризики: (1) CSRF для cookie-мутацій (ЛР 6); (2) роль у cookie живе до оновлення сесії; (3) два одночасні triage теоретично можуть обидва пройти (немає optimistic concurrency); (4) різниця у часі відповіді між «невідомий» і «чужий» id не вимірювалась; (5) audit лише в журналі процесу; (6) delete каскадно видаляє коментарі й історію.

## Перевірки, відтворення і подання (усі рівні)
Середовище: ⟦Windows ‹версія›⟧, .NET SDK ⟦dotnet --version⟧, PostgreSQL ⟦версія образу з infra/compose.yaml⟧.
Команди: `docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait`; `dotnet run --project src/SecureLab.Api -- --reset-database`; `dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release`; `dotnet run --project src/SecureLab.Api --launch-profile http`.
Фактично: Passed ⟦N⟧, Failed ⟦0⟧, Skipped ⟦S⟧ (⟦дата⟧); ручний прогін `lab-04-access.http` (vulnerable) та `lab-04-retest.http` (fixed) — ⟦збігається з очікуваним⟧.
Hash-і: base `v0.3.0` = `2fc1306fbf3a77c4502f8a775d57b827c1c21006`; C1 `eceb51ce0ac44af48f472ac1f47d5d2c0886282a`; C2 `cff86ede3c1afdec9460266ab8421fc360970b70`; vulnerable V = `239a6709aaf66fabdf2bfd0c2da918f454819eaa`; F1 = `8b37a3eb874dfe5d52d2a9fc4528371abc2b2bb7`; E = `⟦hash E⟧`; fixed F2 = `e93897e379a324ecb22ea88b2a2ca3d286ba69d4` 
Посилання: ⟦private remote / MR⟧; Moodle: той самий `docs/report-lab-04.md`.


