# Звіт до лабораторної роботи № TODO

## 1. Ідентифікація стану

- Варіант: 2-A «Трекер інцидентів».
- Гілка: lab01/1-system.
- Фінальний тег: v0.1.0.
- Commit hash: `TODO`.

## 2. Змінений маршрут

Реалізовано GET /api/incidents/severity-summary з необов'язковим query-параметром status. Маршрут: клік кнопки «Показати підсумок» у Client/index.html → loadSeveritySummary у Client/app.js → apiFetch("/api/incidents/severity-summary") → IncidentEndpoints.GetSeveritySummaryAsync (прив'язка status з query, валідація через Enum.TryParse<IncidentStatus> + Enum.IsDefined, 400 Validation Problem Details при некоректному значенні) → IncidentQueries.GetSeveritySummaryAsync (dbContext.Incidents.AsNoTracking(), необов'язковий Where(status), GroupBy(incident => incident.Severity), доповнення відсутніх рівнів severity значенням count: 0 — політика «повний перелік», явний порядок Critical → High → Medium → Low) → SecureLabDbContext.Incidents → таблиця incidents у PostgreSQL → IncidentSeveritySummaryResponse (JSON, 4 елементи) → renderSeveritySummary → виведення через textContent у список <ul id="summary-list">.
Ключовий фрагмент (IncidentQueries.cs):
var orderedSeverities = new[]
{
    IncidentSeverity.Critical, IncidentSeverity.High,
    IncidentSeverity.Medium, IncidentSeverity.Low,
};

var result = orderedSeverities
    .Select(severity => new IncidentSeveritySummaryResponse(
        severity.ToString(), lookup.GetValueOrDefault(severity, 0)))
    .ToList();
## 3. Виконані зміни

src/SecureLab.Api/Presentation/Contracts/IncidentResponses.cs — доданий record IncidentSeveritySummaryResponse(string Severity, int Count).
src/SecureLab.Api/Application/Incidents/IncidentQueries.cs — доданий метод GetSeveritySummaryAsync(IncidentStatus? status, string traceId, CancellationToken cancellationToken): групування за severity, повний перелік 4 рівнів (політика «full enum»), необов'язковий фільтр за статусом, структурований лог (GroupCount, StatusFilter, TraceId).
src/SecureLab.Api/Presentation/Endpoints/IncidentEndpoints.cs — замінено handler-заготовку (яка завжди повертала 501) на GetSeveritySummaryAsync: прив'язка status з query, серверна валідація за allowlist значень IncidentStatus, виклик query, Results.Ok(...).
src/SecureLab.Api/Client/index.html — додана секція з кнопкою #summary-button, статус-рядком #summary-status і контейнером #summary-list.
src/SecureLab.Api/Client/app.js — додані функції renderSeveritySummary і loadSeveritySummary (три стани: завантаження / порожній результат / безпечна помилка), підключення до кліку кнопки; вивід виключно через textContent/ createElement, без innerHTML.
tests/http/incidents.http — додано 4 сценарії для severity-summary: без фільтра, з валідним фільтром (Triaged), з фільтром без збігів (Closed), з некоректним фільтром (Unknown).
tests/SecureLab.Api.Tests/IncidentEndpointTests.cs — додано 3 інтеграційні тести: повний список з 4 елементів, 400 для некоректного статусу, усі нулі для статусу без збігів.
docs/architecture.md — доданий маршрут ЛР 1 і заповнена таблиця меж довіри (5 рядків із конкретними спостереженнями).

## 4. Перевірка

| ID | Передумови | Дія | Очікувано | Фактично | Доказ |
T-01	PostgreSQL healthy, API запущено	GET /health	200	200, {"status":"ready"}	.http response
T-02	відновлений seed	GET /api/incidents?status=Triaged	200, відфільтрований список	200, 1 інцидент (Alice, «Підозрілий лист із вкладенням», Medium)	DevTools Network + .http response
T-03	відновлений seed	GET /api/incidents?status=Resolved	200 з []	200, [] (у seed немає інцидентів зі статусом Resolved)	.http response
T-04	відновлений seed	GET /api/incidents/99999999-9999-9999-9999-999999999999	404 Problem Details	404, Content-Type: application/problem+json, title: "Інцидент не знайдено", власний traceId	.http response
T-05	відновлений seed	GET /api/incidents?status=Unknown	400 Validation Problem Details	400, поле status з переліком допустимих значень	.http response
T-06	реалізовано, відновлений seed	GET /api/incidents/severity-summary	200, 4 елементи (Critical/High/Medium/Low)	200, Critical:0, High:1, Medium:1, Low:1	.http response
T-06b	реалізовано	GET /api/incidents/severity-summary?status=Triaged	200, підрахунок лише серед Triaged	200, Critical:0, High:0, Medium:1, Low:0 (лише інцидент Alice)	.http response
T-06c	реалізовано	GET /api/incidents/severity-summary?status=Closed	200, усі count: 0	200, Critical:0, High:0, Medium:0, Low:0 (у seed немає закритих)	.http response
T-06d	реалізовано	GET /api/incidents/severity-summary?status=Unknown	400 Validation Problem Details	400, поле status з переліком допустимих значень	.http response
T-07	реалізовано, API і клієнт запущено	натиснути кнопку «Показати підсумок»	UI безпечно показує результат; код містить стани завантаження/порожньо/помилки	Список з'явився на сторінці, запит GET /api/incidents/severity-summary видно в DevTools Network зі статусом 200; app.js не містить innerHTML	скриншот UI + DevTools Network
T-08	після dotnet run ... -- --reset-database	повторити T-02 і T-06	seed повертає стенд до відомого стану, результати ідентичні	результати T-02 і T-06 після reset повністю збіглися з початковими	повторний .http response

## 5. Security-сценарій

Не застосовується для ЛР 1: starter навмисно не містить навмисно вразливого стану для цієї роботи (baseline без автентифікації й авторизації). Security- сценарій із гіпотезою, локальним PoC, першопричиною, виправленням і позитивною регресією буде оформлено, починаючи з ЛР 2 (пошук у title/description, параметризація значень і allowlist сортування — за docs/variant-02-a.md, профіль «Пошук»).
## 6. Висновок

Систему запущено локально (PostgreSQL у Docker Compose, API на .NET SDK 10.0.302/ASP.NET Core, browser client на Vanilla JavaScript). Простежено повний маршрут GET /api/incidents/{id} від кліку в браузері до таблиці incidents у PostgreSQL і назад через DevTools Network, код endpoint/query/ DbContext і пряму SQL-звірку; підтверджено 5 меж довіри на цьому шляху. Реалізовано наскрізне розширення GET /api/incidents/severity-summary з політикою «повний перелік severity» (усі 4 рівні, включно з count: 0 для відсутніх) та необов'язковим query-параметром status (серверна валідація через allowlist на базі Enum.TryParse/Enum.IsDefined, 400 для некоректного значення). Успішний, порожній і помилковий сценарії перевірено через .http-файл (7 сценаріїв для severity-summary і суміжних маршрутів) і DevTools Network; додано 3 інтеграційні тести (разом із базовими — 7/7 зелених). Клієнт безпечно відображає результат через textContent/ createElement, без використання innerHTML. Стенд відтворюється командою --reset-database до того самого seed-стану.