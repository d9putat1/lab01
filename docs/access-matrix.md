# Матриця контролю доступу — Incident (baseline 2-A, ЛР 4)

Рішення сервера приймається для комбінації **суб'єкт + дія + ресурс + контекст**. Суб'єкт — лише verified principal (`HttpContext.User`, cookie, видана сервером).
Роль — лише server-issued role claim (`Reporter`, `Analyst`, `Administrator`), призначений ASP.NET Core Identity. Role/owner/status з body, query, заголовка чи JavaScript
**не є входом авторизації**. Усе, що не дозволено явно, заборонено (deny by default).

## Політика відмов (однакова для всього периметра)

1. **Немає authentication** → `401 Unauthorized` (Problem Details, без HTML-redirect).
2. **Principal не має права Read на ресурс** (чужий інцидент для Reporter/Administrator) → `404 Not Found`, **та сама відповідь**, що й для неіснуючого id:
   однакові status, `Content-Type` і тіло (`title: «Інцидент не знайдено»`, без `detail` і без id); відрізняється лише `traceId`. Це політика зменшеної видимості:
   API не підтверджує існування чужого ресурсу.
3. **Principal має право Read, але не має права на дію** (Analyst → update/delete; Reporter → triage; owner → delete не-`New`) → `403 Forbidden`.
   Існування ресурсу такому principal уже відоме, тому прихована відповідь нічого не дала б.
4. **Дію дозволено, але стан ресурсу не підходить** (triage не-`New`) → `409 Conflict`.
5. Перевірка завжди **передує** response і будь-якій зміні стану; перевірка права — **раніше за валідацію body** (щоб чужий запит із некоректним body
   теж отримав 404, а не 400 і не розкрив існування ресурсу).

## Матриця

| Дія | Рівень | Анонім | Reporter | Analyst | Administrator | Власник ресурсу має значення? | Стан реалізації |
|---|---|---|---|---|---|---|---|
| Перегляд списку `GET /api/incidents` | добрий | deny, 401 | allow лише власні інциденти (чужих у відповіді немає) | allow усі інциденти (потрібно для аналізу) | allow лише власні (права на чужі прямо не опубліковано) | Так для Reporter і Administrator; для Analyst — ні | query scoping `IncidentQueries.GetListAsync(status, userId, canReadAll)`; тести A-05 |
| Пошук `GET /api/incidents/search` | відмінний (A-11) | deny, 401 | allow лише власні | allow усі | allow лише власні | Так для Reporter і Administrator; для Analyst — ні | `Lab02Endpoints`: `RequireAuthorization()` + умова `canReadAll \|\| OwnerUserId == userId` у запиті до сортування і `Take(50)`; тести `SearchAndSummaryScopingTests` (A-11) |
| Зведення `GET /api/incidents/severity-summary` | відмінний (A-11) | deny, 401 | allow, агрегати лише власних інцидентів | allow, агрегати всіх | allow, агрегати лише власних | Так для Reporter і Administrator; для Analyst — ні | `IncidentQueries.GetSeveritySummaryAsync(status, userId, canReadAll, …)`: умова до `GroupBy`; тести `SearchAndSummaryScopingTests` (A-11) |
| Перегляд деталей `GET /api/incidents/{id}` | достатній: entry-контракт ЛР 5 (головна action) | deny, 401 | owner — allow, 200; non-owner — deny, 404 як для неіснуючого | allow, 200 (читає будь-який інцидент для аналізу) | owner — allow; non-owner — deny, 404 | Так (для Reporter/Administrator) | handler `IncidentOperations.Read`; тести A-01, A-02, A-03, A-03R, A-10 |
| Створення інциденту `POST /api/incidents` | успадкований baseline (ЛР 3) | deny, 401 | allow for self, 201, owner = principal | allow for self | allow for self | Сервер призначає власника з principal | перевіряється регресією ЛР 3, не змінюється |
| Update content `PUT /api/incidents/{id}` (лише `title`, `description`) | добрий | deny, 401 | owner — allow, 200; non-owner — deny, 404 | deny, 403 (бачить інцидент, але вмісту не змінює) | owner — allow; non-owner — deny, 404 | Так | handler `IncidentOperations.Update`; тести A-04, A-08a, A-03R (mutation) |
| Delete `DELETE /api/incidents/{id}` | добрий | deny, 401 | owner **і** статус `New` — allow, 204; owner, статус не `New` — deny, 403; non-owner — deny, 404 | deny, 403 | owner і `New` — allow; non-owner — deny, 404 | Так | handler `IncidentOperations.Delete`; тести A-04 |
| Зміна status: triage `POST /api/incidents/{id}/triage` | добрий | deny, 401 | deny, 403 (навіть для owner); чужий інцидент — deny, 404 | allow лише `New → Triaged`, 200; інший статус — 409 | non-owner — deny, 404 (права triage немає) | Ні (дозвіл дає роль, не володіння) | handler `IncidentOperations.Triage` + перевірка статусу; audit; тести A-06, A-07, A-09 |
| Зміна severity | добрий | deny, 401 | deny (endpoint відсутній, поля немає в DTO) | deny (endpoint відсутній) | deny (endpoint відсутній) | — | не реалізується; захищено відсутністю поля в `UpdateIncidentRequest` (A-08a) |
| Перегляд internal comment у details | добрий | deny, 401 | deny: коментар відсутній у відповіді (навіть для власника) | allow після дозволу на Read parent | deny: відсутній | Ні | handler `IncidentOperations.ReadInternalComments`; тест A-12 |
| Прямий child `GET /api/incident-comments/{id}` | добрий | deny, 401 | публічний коментар **власного** інциденту — allow, 200; коментар чужого інциденту — deny, 404; internal — deny, 404 (навіть для власного інциденту) | allow після Read parent; internal — allow | як Reporter: лише коментарі власних інцидентів, internal — 404 | Так, через parent incident | `IncidentCommentEndpoints` + handler на parent; тести A-12 |
| Export/audit | відмінний, лише якщо flow існує | — | — | — | — | — | у проєкті такого flow немає: **не застосовується** |
| Batch endpoint | відмінний, лише якщо існує | — | — | — | — | — | у проєкті немає: **не застосовується** |

## Умови словами (де в клітинках стоїть «умова»)

- **Update content**: власник інциденту; змінюються лише `title` і `description`; після зміни інцидент із severity High/Critical має мати опис ≥ 40 символів;
  `title` не повинен збігатися з активним (New/Triaged/InProgress/Resolved) інцидентом (409 — як у create).
- **Delete**: власник **і** `Status == New`. Інцидент, який уже опрацьовує аналітик (Triaged і далі), стерти разом із історією не можна — це авторське рішення, узгоджене з аудитною цінністю історії.
- **Triage**: роль Analyst (server-issued claim) **і** поточний статус `New`; наступний статус `Triaged` встановлює сервер, у запиті його немає.
- **Internal comment**: лише Analyst, і лише якщо йому дозволено Read parent incident.

## Least privilege (чому кожна роль має саме ці права)

- **Reporter** повідомляє про власні інциденти: створює, бачить і редагує тільки свої; бачити чужі — не потрібно для його задачі.
- **Analyst** розглядає інциденти всіх: тому читає всі й internal-нотатки; але його єдина змінювальна дія — первинна оцінка `New → Triaged`. Довільне редагування вмісту чужих
  звітів чи видалення йому не потрібні (це зламало б довіру до першоджерела).
- **Administrator** у baseline 2-A не має опублікованих прав на Incident: роль не дає автоматичного обходу ownership.