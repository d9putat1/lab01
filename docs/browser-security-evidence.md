Докази безпеки браузера (DEL-01)

Рівень: відмінний («Відмінно»). Рівні накопичувальні; нижче заповнено розділи для всіх рівнів, для «Добре» та для «Відмінно». Паролі, значення cookie/token і export browser storage не записувались.

Скріншоти й консольні виводи зібрано у файлі lab5.docx (додається до здачі). Посилання «рис. N» — це номер зображення за порядком у цьому файлі.

Стенд і Git-стан (Для всіх)

ОС, browser/version, API/probe origins: Windows, PowerShell; браузер Chromium-based ⟨назва і версія⟩; API http://localhost:5080 (dotnet run --project src/SecureLab.Api), probes http://localhost:4173 (allowed) і http://localhost:4174 (disallowed), запущені через py -3 -m http.server <port> --bind localhost --directory demonstrations/cors-probe (рис. 25). БД — PostgreSQL з infra/compose.yaml.

Release/base_commit/entry_parent з receipt .scaffolds/lab-05.json: release lab-05-start-v1; inherits v0.4.0; base_commit = entry_parent = 645826f48ea06981c8a9c6e095562c2091f40b38 (збігається з git rev-parse v0.4.0^{commit}).

Vulnerable/fixed hashes, v0.5.0, main і спосіб передавання:

Етап	Commit	Що змінено
Vulnerable (scaffold)	d6bb2df74b0592975b85d6e804a9160b4310c972	встановлено lab-05-start-v1, sink-и innerHTML (рис. 1, 2)
Seed fixture коментаря	6678567cd661ed74f05204d5de5ca0d78b4c6a60	seed-коментар 30000000-…-000000000005 з marker (DbSeeder.cs)
XSS fix	8167a826023e6ffabbe4264d1ce6b295df06e895	safe DOM: helper renderText + textContent для description і comments
CORS	21e6fce1d31110561143395461afe478bda07812	Development-policy Lab05BrowserProbe, exact origin 4173
Fixed (код)	e8f4c90bf7ad6a9ec2fcfb25b9c209028f9e5769	CSP у enforcement + наявні nosniff/Referrer-Policy
Тести й чернетки docs	7649a7137d25e7675e28e67637332a16f5caa30e	tests/browser/description-dom.js

Тег v0.5.0 ⟨hash⟩ ставиться на останній коміт (fixed code commit + лише docs/ і tests/browser/); git diff --stat e8f4c90..v0.5.0 не показує змін у src/. Передавання: remote origin (github.com/d9putat1/lab01) із доступом викладача ⟨підтверди⟩; main після злиття ⟨hash⟩.

Механізм сеансу (Application → Storage → Cookies → http://localhost:5080): cookie .AspNetCore.Identity.Application; Domain — host-only localhost; Path /; HttpOnly — так; SameSite — Lax (за Set-Cookie, рис. 44); Secure — ⟨перевір у Application → Cookies; стенд працює по http⟩. Значення cookie не копіювалось.

Гіпотеза й REG-XSS-01 (Для всіх)

Карта Description: див. docs/source-to-sink.md (textarea description → POST /api/incidents → валідація Lab02Endpoints.cs (обов'язкове, ≤ 4000, Trim) → колонка description → GET /api/incidents/{id} (IncidentDetailsResponse.Description) → load() у browser-lab.js → #description).

Гіпотеза: значення з textarea description зберігається в incidents.description, повертається в JSON-полі description відповіді GET /api/incidents/{id} і передається в #description.innerHTML як HTML-контекст; тому за наявності в значенні розмітки браузер може інтерпретувати дані не як звичайний текст, а як елемент.

Передумови: локальні користувачі alice (автор), morgan (Analyst), bob (контроль); пароль береться зі змінної SeedUsers__Password (у докази не вносився); marker — рядок із resources/lab05-marker.txt без змін; запис LR5 marker1 (Guid 4d8a883c-064f-46f9-8783-d2c5… ⟨допиши повний Guid з рис. 15⟩), створений Alice через форму «Створити й прочитати» (рис. 12). Скидання БД: dotnet run --project src/SecureLab.Api -- --reset-database; запуск: dotnet run --project src/SecureLab.Api.

Спостереження	До fix	Після fix	Посилання на доказ
Значення в БД/API	POST /api/incidents → 201, GET /api/incidents/{id} → 200, description містить marker як рядок	код створення/читання (Lab02Endpoints.cs, IncidentQueries.cs, entity, DTO) між v0.4.0 і fixed не змінювався (git diff --stat v0.4.0..e8f4c90 для цих файлів порожній); DOM-тест порівнює textContent з description з API і проходить	рис. 12; рис. 49
DOM основного Description	в <div id="description"> створено елемент <img src="x" onerror="…">, на екрані «зламане» зображення	в #description лише текстовий вузол, на екрані видно сам рядок marker	рис. 13, 15; рис. 24
Дія marker	#lab05-marker-target отримав data-lab05-marker="executed"; браузер відправив запит x (відповідь 200 text/html — fallback застосунку)	запит x не надсилається; атрибут лишається null (перевірка в DOM-тесті «Marker executed»)	рис. 11 (до виконання: null), рис. 12, 13; рис. 24, 49
Апостроф/лапки, 5 < 7, Unicode, HTML-like рядок	O'Brien … "терміново", 5 < 7 і 9 > 3, Київ — Ω відображені як є; <b>жирний</b> текст — слово напівжирне, дужок немає (HTML інтерпретовано)	усі чотири відображаються як є; <b>жирний</b> текст видно буквально	рис. 7–10; рис. 19–22
Довжина за власними правилами ЛР 2	—	⟨4000 символів (copy("А".repeat(4000))): відображається, у Console помилок немає — додай скріншот⟩	⟨рис.⟩
Вікно Morgan: GET і перевірка marker; контроль Bob	Morgan (Analyst): вхід Login: 204, GET: 200 для запису Alice, відображено «зламане» зображення — код, збережений Alice, інтерпретовано в сеансі Morgan; Bob: вхід 204, GET: 404 за матрицею ЛР 4 (це контроль авторизації, а не доказ XSS)	⟨Morgan на тому самому Guid: marker відображається текстом, перевірка → null — додай скріншот⟩	рис. 14–17

Finding: актив — сеанс користувача в браузері та дані, доступні від його імені (Analyst бачить чужі записи в межах матриці ЛР 4). Передумови: локальний обліковий запис, що може створити інцидент, і сторінка, на якій його значення виводиться іншим користувачем. Першопричина: недовірений current.description (і comment.text) передавався в HTML-sink innerHTML у load() файлу browser-lab.js; браузер парсив рядок як розмітку. Вплив на стенді: marker виконав лише локальну DOM-дію (атрибут на прихованому <span>), без читання cookie/storage і без зовнішніх запитів. Класифікація: stored XSS (значення збережене в БД і виконується під час пізнішого перегляду іншим користувачем) і водночас DOM-based (небезпечне перетворення — innerHTML на клієнті). Safe DOM diff: innerHTML = … → renderText(element, value) (element.textContent = value ?? "") для description і кожного comment.text; створення <p> — кодом, дані — лише текстом (коміт 8167a82). Retest: той самий marker і той самий механізм створення запису — marker показано текстом (рис. 24), DOM-тест PASS (рис. 49). Залишковий ризик: інші поля/екрани з innerHTML (на момент перевірки в Client/*.js збігів немає — рис. 18), сторонній код (Scalar), contexts URL/атрибута, якщо з'являться посилання з даних.

Повторювана REG-XSS-01:

Передумови: fixed commit e8f4c90; --reset-database; API запущено; користувачі alice/morgan (пароль у SeedUsers__Password); http://localhost:5080.
Вхід: marker з resources/lab05-marker.txt без змін.
Кроки: /auth-lab.html → Alice → /browser-lab.html → створити інцидент із marker в описі → «Створити й прочитати»; у вікні Morgan відкрити той самий Guid; у Console виконати document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker").
Очікування: marker відображається як текст; в #description один текстовий вузол; результат перевірки null; звичайний текст працює.
Негативний контроль: на vulnerable commit d6bb2df marker виставляє executed (рис. 13); DOM-тест tests/browser/description-dom.js там падає (рис. 50).
CORS і REG-CORS-01 (Для всіх)

Прогноз (Етап 3, крок 1), заповнено до зміни policy:

Сценарій	Чи доходить request до API?	Чи може JavaScript прочитати response?	Чому
same-origin 5080 → API	так	так	той самий origin, CORS не потрібен
simple GET 4173 → API	так (простий запит надсилається)	ні, поки немає Access-Control-Allow-Origin	SOP/CORS браузера
simple GET 4174 → API	так	ні	origin не в allowlist
curl/.http → API	так	не застосовується	це не браузерний JavaScript
preflighted 4173 → API	спершу OPTIONS; actual GET залежить від відповіді на preflight	ні без успішного preflight	preflight + CORS

Команди запуску probes (з кореня проєкту):

py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe
py -3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe

Policy Lab05BrowserProbe — лише Development, один exact origin http://localhost:4173, метод GET, заголовок X-Lab-Cors-Probe; 4174 — негативний контроль. UseRouting() і UseCors(...) стоять перед UseAuthentication()/UseAuthorization()/UseRateLimiter() (рис. 29, 30).

Клієнт / простий запит	До policy	Fixed state	Status, ACAO, Console / доказ
Same-origin 5080	fetch("/health") → {status: 200, body: '{"status":"ready"}'}	без змін	рис. 31
Allowed 4173	Failed to fetch; «No 'Access-Control-Allow-Origin' header»; у Network запит GET /health дійшов (200 (OK) net::ERR_FAILED)	curl з Origin: 4173 → 200 OK і Access-Control-Allow-Origin: http://localhost:4173; ⟨у браузері з 4173: {status: 200, …} — додай скріншот⟩	рис. 26, 33; рис. 48
Disallowed 4174	Failed to fetch; «No 'Access-Control-Allow-Origin' header»	curl з Origin: 4174 → 200 OK без Access-Control-Allow-Origin (браузер не віддасть response коду сторінки); ⟨у браузері з 4174 — Failed to fetch після policy, додай скріншот⟩	рис. 34; рис. 48
Direct HTTP / curl	200 (/health, також з Origin: 4174), 401 для /api/incidents без входу; читається повністю	без змін; додано лише CORS-заголовок для 4173	рис. 32, 35; рис. 48

Preflight до policy: fetch із заголовком X-Lab-Cors-Probe → OPTIONS /health зі статусом 405, actual GET не надсилався; Console: «Response to preflight request doesn't pass access control check» (рис. 27, 28). Після policy: ⟨OPTIONS → 204 з Access-Control-Allow-Origin/Headers/Methods, потім GET → 200 для 4173; для 4174 — OPTIONS без Access-Control-*, actual GET не надсилається — додай скріншоти⟩.

REG-CORS-01: browser evidence — probes 4173/4174 → API 5080 з абсолютним URL і Origin у запиті (рис. 26–28, 33, 34; після policy ⟨рис.⟩). Дві actual HTTP-відповіді для Origin 4173/4174 (fixed state, curl.exe -sS -D - -o NUL -H "Origin: …" http://localhost:5080/health): обидві HTTP/1.1 200 OK з X-Content-Type-Options: nosniff, Referrer-Policy: no-referrer, Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; лише перша має Access-Control-Allow-Origin: http://localhost:4173 (рис. 48). Перевірка порядку через читання 401 без cross-origin cookie: ⟨fetch("http://localhost:5080/api/incidents") на 4173 → 401, без слів «blocked by CORS» — додай скріншот; curl без входу вже дає 401, рис. 35⟩. Пояснення різниці browser/direct HTTP: curl читає відповідь, бо same-origin policy — правило браузера для веб-контенту; API при цьому однаково застосовує authentication, authorization і validation до будь-якого клієнта. Статус 200 для 4174 — не помилка: сервер запит виконав, а відповідь коду сторінки не віддає браузер. CORS не є авторизацією.

Додатково для Добре та Відмінно

Другий flow IncidentComment.Text: public seed-коментар 30000000-0000-0000-0000-000000000005 (автор Morgan, IsInternal = false) у seed-інциденті Alice 20000000-0000-0000-0000-000000000001 з marker у Text (коміт 6678567); sink — цикл коментарів у load(). До fix <p> отримував innerHTML; після fix — текст. DOM до/після: ⟨скріншот Elements #comments до/після і результат tests/browser/comments-dom.js⟩. Єдиний safe helper renderText(element, value) використовується для обох полів: renderText(document.querySelector("#description"), current.description) і commentsBox.append(renderText(document.createElement("p"), comment.text)); replaceChildren() перед циклом не дає дублювати коментарі при повторному load(). У Client/*.js збігів innerHTML немає (рис. 18).

Preflight з 4173 і 4174, OPTIONS → GET / blocked GET, exact origin/header/method: ⟨додай скріншоти після policy; до policy — рис. 27, 28⟩. Cookie-дослід 4173/4174/без AllowCredentials()/401 без входу: ⟨потребує .AllowCredentials() у Development-policy для 4173 — виконати за кроками 3.6 плану й записати результат⟩. Кінцевий AllowCredentials() — лише Development policy для 4173 ⟨після виконання досліду⟩. Review XSS/CORS/CSRF/authorization — у docs/report-lr05.md.

Директива CSP	Фактичні ресурси застосунку	Обране джерело / причина
default-src	усі ресурси власні (same-origin); зовнішніх URL немає	'self' — fallback для всіх типів
script-src	лише власні <script src>: /app.js, auth-lab.js, session-flow.js, browser-lab.js; inline-скриптів і onclick немає	через default-src 'self'; unsafe-inline не потрібен
style-src	власний styles.css; inline-стилів (style=) немає	через default-src 'self'
connect-src	fetch лише на /api/... того ж origin	через default-src 'self'
img-src	зображень немає; контроль — new Image() до 4173 заблоковано	через default-src 'self' (рис. 39, 43)
frame-ancestors	застосунок не має вбудовуватись	'none'; не має fallback до default-src, тому вказано явно

Місце зміни middleware: наявна app.Use(...) у Program.cs (після UseStatusCodePages, до UseDefaultFiles), де вже були X-Content-Type-Options і Referrer-Policy; CSP встановлюється для всіх відповідей, окрім Development-довідника /scalar. Enforcement: curl -sS -D - -o NUL http://localhost:5080/ → 200 OK і рівно один Content-Security-Policy: default-src 'self'; frame-ancestors 'none' (рис. 42, 45); кероване порушення new Image().src = "http://localhost:4173/x.png" → «violates … "default-src 'self'" … The action has been blocked» (рис. 43). Три сторінки flow під enforcement: ⟨пройти /, /auth-lab.html, /browser-lab.html — у Console немає Refused …; додай підтвердження⟩. Для «Добре» докази report-only не обов'язкові (див. розділ «Відмінно»).

Header / control	Фактичне значення	Ризик і межа захисту / policy rationale
X-Content-Type-Options	nosniff (рис. 45)	браузер не вгадує MIME-тип за вмістом; не замінює правильний Content-Type і validation
Referrer-Policy	no-referrer (рис. 45)	URL сторінки (з ідентифікаторами інцидентів) не потрапляє в Referer; клієнт — один same-origin застосунок без зовнішніх переходів, referrer не потрібен; не замінює правило не класти secrets в URL
frame-ancestors	'none' у CSP (рис. 45)	забороняє вбудовування в <iframe> (clickjacking); перевірено: Framing 'http://localhost:5080/' violates … "frame-ancestors 'none'". The request has been blocked. (рис. 46, 47); не замінює authorization і виправлення XSS. X-Frame-Options не додано — frame-ancestors покриває цю загрозу
Додатково для Відмінно

DOM-тест: файл tests/browser/description-dom.js (вставляється в Console на /browser-lab.html після входу й оновлення сторінки, з Guid запису з marker у полі). Browser: ⟨назва і версія⟩. На vulnerable commit d6bb2df — FAIL: Error: Text changed (рис. 50). На fixed e8f4c90 — PASS: PASS: persisted description rendered as plain text (рис. 49). Нюанс: під час запуску на vulnerable у відповіді ще діяв CSP із зібраного fixed-процесу API — тому Console показує «Executing inline event handler violates … Content Security Policy … The action has been blocked», і marker не виконався; проте DOM-перевірка однаково впала. Це підтверджує, що CSP маскує невиправлений sink, і висновок «sink виправлено» грунтується на DOM (текстовий вузол замість <img>), а не на відсутності спрацювання marker.

Comments, повторний render без дублювання та позитивні рядки: ⟨tests/browser/comments-dom.js для 20000000-0000-0000-0000-000000000001: PASS на fixed і FAIL на vulnerable; позитивні рядки (O'Brien, 5 < 7, Unicode) порівнюються з JSON API — додай результат⟩. Ручна позитивна регресія виконана (рис. 19–22).

CSP report-only → enforcement: у report-only (Content-Security-Policy-Report-Only: default-src 'self'; frame-ancestors 'none') заголовки видно на /, /browser-lab.html, /auth-lab.html (рис. 36–38); кероване порушення залогувалось, але не заблокувало: «The policy is report-only, so the violation has been logged but no further action has been taken»; запит до x.png виконувався й завершився помилкою мережі (рис. 39, 40). Enforcement: заголовок Content-Security-Policy (рис. 41, 42, 45), порушення заблоковано (рис. 43). Одна й та сама middleware, змінено лише ім'я заголовка; два CSP одночасно не виставляються.

safe-url.js / атрибут: safeHttpUrl(value, base) розбирає URL через new URL() і пропускає лише http:/https:; вивід: https://example.com/a, http://localhost:5080/incidents/1, три null (javascript:alert(1),  JaVaScRiPt:alert(1), http://[::bad]), створене посилання має href і не має onclick (рис. 23). Пояснення text/attribute/URL/JavaScript та ризик third-party scripts — у docs/report-lr05.md. Third-party: у власному коді клієнта сторонніх <script src> немає; єдиний сторонній UI — Scalar (/scalar), лише Development і виключений з CSP — залишковий ризик, його аудит — у ЛР 6.

Додаткових DEL, навчальних демо або нового журналу не подано.