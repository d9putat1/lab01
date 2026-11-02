# Звіт WEB ЛР 5

Автор: Tokarchuk Vlad ⟨група⟩. Спільний сценарій 2-A. Рівень: відмінний («Відмінно»). ОС/browser: Windows, ⟨браузер і версія⟩. Достатній = «Задовільно»; добрий = «Добре»; відмінний = «Відмінно».

Скріншоти й виводи консолі зібрано у `lab5.docx`; «рис. N» — номер зображення за порядком у ньому.

## Для всіх рівнів

### DEL-01

Власна карта: `docs/source-to-sink.md`. Докази: `docs/browser-security-evidence.md`.

Коротко: до → причина → fix → retest → залишковий ризик.

| Етап | Опис |
|---|---|
| До | Marker у полі `description` (і в `comments[].text` seed-коментаря) перетворювався `innerHTML` на елемент `<img onerror=…>` і виконувався в сеансі іншого користувача (Morgan). `#lab05-marker-target` отримував `data-lab05-marker="executed"` (рис. 12–15). |
| Причина | Недовірений рядок із API потрапляв у HTML-sink (`innerHTML`) у `load()` файлу `browser-lab.js`, тож браузер парсив його як розмітку. Проблема не в «поганому слові `script`», а в контексті виведення. |
| Fix | Єдиний helper `renderText(element, value)` → `element.textContent`; структуру задає код (`createElement("p")`), дані потрапляють лише в текстовий вузол. Сервер і БД не змінювались: значення зберігається як є (коміт `8167a82`). |
| Retest | Той самий marker відображається текстом, запиту `x` немає, перевірка атрибута → `null` (рис. 24); позитивні рядки (лапки, `<`/`>`, Unicode, HTML-like) відображаються буквально (рис. 19–22); DOM-тест FAIL на vulnerable і PASS на fixed (рис. 50, 49). |
| Залишковий ризик | Інші поля/екрани з `innerHTML` (зараз у `Client/*.js` їх немає, рис. 18); контексти URL/атрибута, якщо з'являться посилання з даних; сторонній код (Scalar, лише Development); CSP — додатковий шар, а не заміна safe DOM. |

### DEL-02

- `release`: `lab-05-start-v1`; `base_commit` = `645826f48ea06981c8a9c6e095562c2091f40b38` (тег `v0.4.0`).
- Vulnerable commit: `d6bb2df74b0592975b85d6e804a9160b4310c972`.
- Fixed commit (код): `e8f4c90bf7ad6a9ec2fcfb25b9c209028f9e5769`. Проміжні: seed `6678567`, XSS fix `8167a82`, CORS `21e6fce`.
- `v0.5.0` → ⟨hash⟩ — fixed code commit плюс лише `docs/` і `tests/browser/` (`git diff --stat e8f4c90..v0.5.0` не показує змін у `src/`).
- Передавання: приватний remote `origin` (`github.com/d9putat1/lab01`) із доступом викладача ⟨підтверди⟩; `main` → ⟨hash злиття⟩; перевірка: `git show --no-patch v0.5.0` і `git log --oneline --decorate -n 10` ⟨додай вивід⟩.
- `dotnet test`: ⟨N⟩ passed, 0 failed (тести не змінювались).

### DEL-03: відповіді на контрольні питання

1. **Чому дані з БД не довірені для браузера?** БД лише зберігає рядок. Значення прийшло від користувача, а чи безпечне воно, залежить від контексту виведення. У мене в БД лежав той самий marker, і в HTML-контексті він став кодом.
2. **Source → sink мого Description.** Source — textarea `description` у `browser-lab.html`. Далі `POST /api/incidents` → валідація в `Lab02Endpoints.cs` (обов'язкове, ≤ 4000, `Trim`) → колонка `description` → `GET /api/incidents/{id}` → поле JSON `description` → `load()` → `#description.innerHTML`.
3. **Stored / reflected / DOM-based.** Stored — значення збережене й виконується пізніше (у мене: Alice зберегла, Morgan відкрив). Reflected — значення повертається у відповіді на той самий запит. DOM-based — небезпечне перетворення відбувається на клієнті. Мій випадок stored і DOM-based одночасно; ознаки не виключають одна одну.
4. **Чому фільтр `<script>` не лікує.** Виконання дає й `<img onerror>`, обробники подій, посилання; чорний список не охоплює всі контексти. Причина — HTML-парсер у sink, тому лікування — не віддавати дані парсеру.
5. **`textContent` чи sanitizer.** Якщо поле — звичайний текст (як тут за контрактом), достатньо `textContent`. Sanitizer потрібен лише тоді, коли продукт навмисно приймає обмежений HTML.
6. **Чому не regexp для sanitizer.** Regexp не повторює розбір HTML браузером і обходиться регістром, пробілами, вкладеністю; потрібна підтримувана бібліотека (наприклад DOMPurify) з мінімальним allowlist.
7. **Origin.** Схема + host + порт: `http://localhost:5080`, `:4173` і `:4174` — три різні origins.
8. **Preflight.** Автоматичний `OPTIONS`, який браузер шле перед «непростим» cross-origin запитом (у мене — через заголовок `X-Lab-Cors-Probe`). Він перевіряє дозвіл CORS, а не авторизацію користувача. Без policy я бачив `405` на `OPTIONS`, і actual `GET` не надсилався (рис. 28).
9. **Хто оголошує і хто застосовує CORS.** API оголошує дозволи заголовками `Access-Control-*`, застосовує — браузер.
10. **Чому `curl` читає відповідь.** CORS/SOP — правило браузера для веб-контенту; `curl` не браузер. Але API однаково застосовує authentication, authorization і validation (`401` для `/api/incidents` без входу, рис. 35).
11. **Що CORS не вирішує.** Не перевіряє право користувача на ресурс і не блокує cookie-запити: запит із недозволеного origin може дійти до API й виконатись, браузер лише не віддасть відповідь сторінці. Це тема CSRF (ЛР 6).
12. **Wildcard і credentials.** `*` не є валідним origin для відповіді з credentials; ASP.NET Core відхиляє policy `AllowAnyOrigin()` + `AllowCredentials()` ще при старті. Origin дозволяється точно.
13. **CSP і sink.** CSP обмежує, що браузер виконує й завантажує, але не виправляє sink: на vulnerable-коді з увімкненим CSP `<img>` усе одно з'являвся в DOM, а inline-обробник блокувався (рис. 50). Тому висновок про виправлення роблю по DOM, а CSP лишається defense in depth.
14. **Headers.** `nosniff` — проти MIME sniffing; `Referrer-Policy: no-referrer` — проти витоку URL у `Referer`; `frame-ancestors 'none'` — проти вбудовування в чужий `<iframe>` (clickjacking, рис. 46, 47). Жоден не замінює authorization і виправлення XSS.

## Додатково для Добре та Відмінно

**IncidentComment.Text.** Seed-коментар `30000000-0000-0000-0000-000000000005` (публічний, автор Morgan) у seed-інциденті Alice містить marker; sink — цикл коментарів у `load()`. Безпечний render через той самий helper `renderText`; `replaceChildren()` перед циклом не дає дублювати коментарі при повторному `load()`. Результат: ⟨`tests/browser/comments-dom.js` — PASS/FAIL і скріншоти⟩.

**Preflight і cookie-дослід.** До policy: `OPTIONS` → `405`, actual `GET` не надсилався (рис. 27, 28). Після policy: ⟨OPTIONS 204 для 4173 і без `Access-Control-*` для 4174⟩. Cookie-дослід (`AllowCredentials()` лише для 4173, 4174 без response, `401` без входу): ⟨результат⟩. Cookie `.AspNetCore.Identity.Application` має `HttpOnly` і `SameSite=Lax`; порти одного `localhost` — це той самий site, тому цей дослід не доводить cross-site поведінку.

**CSP і headers.** Policy `default-src 'self'; frame-ancestors 'none'` складено за фактичними ресурсами: власні скрипти й стилі, без inline-коду, без зовнішніх URL. Enforcement перевірено заголовком (рис. 42, 45) і керованим порушенням `new Image()` до 4173 (рис. 43). `nosniff` і `Referrer-Policy` були в middleware раніше; `no-referrer` підходить, бо клієнт — один same-origin застосунок без зовнішніх переходів. `X-Frame-Options` не додавав: `frame-ancestors 'none'` покриває цю загрозу.

**Review XSS / CORS / CSRF / authorization.** XSS — виконання недовіреного тексту в браузері; лікується safe DOM у sink, і CORS чи authorization його не зупиняють (marker працював у сеансі Morgan, хоча authorization поводилась правильно: Bob отримав `404`, рис. 17). CORS лише визначає, чи браузер покаже cross-origin відповідь JavaScript-коду; від `curl` він не захищає. CSRF — браузер сам додає cookie, і запит із чужого origin може змінити стан; CORS не замінює antiforgery (запит із 4174 доходив до API, хоч відповідь і не читалась) — це ЛР 6. Authorization — рішення сервера про право на дію, однакове для браузера й `curl`. Policy обґрунтовано мінімальністю: один exact origin, один метод, один заголовок, лише Development.

## Додатково для Відмінно

**DOM-тест.** `tests/browser/description-dom.js`, браузер ⟨версія⟩. Vulnerable `d6bb2df` — FAIL `Text changed` (рис. 50); fixed `e8f4c90` — PASS (рис. 49). Нюанс: на vulnerable-запуску CSP ще діяв, marker заблоковано CSP, а тест однаково впав на DOM-перевірці — це підтверджує, що CSP маскує sink.

**Report-only → enforcement.** Спершу `Content-Security-Policy-Report-Only`: заголовки на трьох сторінках (рис. 36–38), порушення залоговано без блокування (рис. 39, 40). Потім у тій самій middleware — `Content-Security-Policy`: заголовок (рис. 42), порушення заблоковано (рис. 43). Одночасно два CSP не виставлялись.

**Comments і повторний render.** ⟨результат `comments-dom.js`: кількість, `textContent`, відсутність дочірніх елементів, відсутність дублювання після другого `load()`⟩. Позитивні рядки вручну: рис. 19–22; автоматично ⟨додай⟩.

**URL/атрибут і правила виведення.** Текст — `textContent`; значення атрибута — не збирати розмітку рядками, задавати через API елемента, для небезпечних атрибутів використовувати allowlist; URL — розбір через `new URL()` і allowlist протоколів `http:`/`https:` (`safeHttpUrl`, рис. 23: `javascript:alert(1)` і ` JaVaScRiPt:alert(1)` → `null`, у створеного посилання немає `onclick`); JavaScript — не складати код із рядків (`eval`, `new Function`, inline-обробники). Formatted HTML у цій роботі не приймається; потрібен був би sanitizer.

**Третя сторона.** У власному клієнті сторонніх скриптів немає; Scalar (`/scalar`, лише Development) виключено з CSP — залишковий ризик, аудит у ЛР 6.

## Межі перевірки

Перевірено фактично: відтворення stored XSS на `Incident.Description` (Alice → Morgan), контроль Bob (`404`), safe DOM для description і коментарів, поведінку CORS для 4173/4174 без policy і з нею через `curl`, CSP у режимах report-only та enforcement, заголовки `nosniff`/`Referrer-Policy`/`frame-ancestors`, DOM-тест FAIL/PASS, `safeHttpUrl`.

Поза стендом: production-конфігурація та HTTPS (`Secure` cookie, HSTS), інші браузери й версії (перевірено лише один), CSRF-захист (ЛР 6), аудит Scalar, інші екрани й поля, яких немає в застосунку. Результати, позначені ⟨…⟩, записуються лише після фактичного виконання відповідного кроку; нереальні PASS не записано.