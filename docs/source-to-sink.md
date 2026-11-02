Власна карта source-to-sink

Поле: Incident.Description. Стан/commit: vulnerable commit ⟨ВСТАВ hash⟩ (scaffold lab-05-start-v1, спадщина v0.4.0). Вхід/Guid запису: ⟨ВСТАВ Guid marker-інциденту⟩ (створений Alice, назва LR5 marker-1).

Замін усі ⟨…⟩ на свої значення. Номери рядків перевір у своєму коді — вони приблизні.

1. Основний потік: Incident.Description (для всіх рівнів)
Крок	Файл та функція/DTO	Конкретне поле/значення	Доказ і довіра
Source	src/SecureLab.Api/Client/browser-lab.html, форма #edit, <textarea name="description" required>	текст, який уводить користувач (у PoC — canonical marker із lab05-marker.txt)	контрольоване користувачем; клієнтські обмеження не є межею довіри
Request	Client/browser-lab.js, обробник submit форми #edit → fetch("/api/incidents", { method: "POST" })	JSON-тіло { "title", "description", "severity": "Low", "occurredAtUtc" }; поле description = значення з textarea	Network → POST /api/incidents → Payload; відповідь 201; контрольоване користувачем
Validation/mapping	Scaffolding/Lab02Endpoints.cs, MapPost("/api/incidents"), DTO CreateIncidentRequest: обов'язковість, довжина ≤ 4000, Trim(), entity Incident (Description = description); .RequireAuthorization(), власник береться з claim, не з тіла	request.Description → description (після Trim)	валідація не робить текст довіреним: символи <, >, лапки не відхиляються (за контрактом Description — звичайний текст); authorization перевіряє право, а не вміст
Storage	Data/Entities/Incident.cs → Description; таблиця/колонка description, HasMaxLength(4000) у Data/SecureLabDbContext.cs; PostgreSQL	те саме значення, дослівно	збережене значення користувача; збереження в БД не робить його довіреним HTML
Response	GET /api/incidents/{id:guid} → Presentation/Endpoints/IncidentEndpoints.cs, GetDetailsAsync (авторизація) → Application/Incidents/IncidentQueries.cs, GetDetailsAsync; DTO Presentation/Contracts/IncidentResponses.cs, IncidentDetailsResponse.Description	JSON-поле description у response	недовірене для відображення браузером; 200 від сервера не означає, що вміст безпечний; JSON-екранування (\") не є захистом від HTML-sink
Client transform	Client/browser-lab.js, load(): current = await response.json()	current.description	перетворень/очищення немає: значення передається в sink без змін
Sink/context	Client/browser-lab.js, load(): document.querySelector("#description").innerHTML = current.description;	HTML-рядок → HTML-парсер браузера	vulnerable: HTML-контекст; marker перетворюється на елемент <img onerror=…> і виконується. Fixed: textContent (див. розділ 3)

Додатково: відповідь POST (CreatedIncidentResponse) також повертає description, але browser-lab.js її не рендерить — після 201 бере лише created.id і викликає load(). Тому sink єдиний — у load().

Класифікація

Stored XSS (значення збережене в БД і виконується під час пізнішого перегляду іншим користувачем, Morgan) і DOM-based (небезпечне перетворення — innerHTML на клієнті). Ознаки не взаємовиключні.

2. Другий потік: IncidentComment.Text (Добре / Відмінно)
Крок	Файл та функція/DTO	Конкретне поле/значення	Доказ і довіра
Source	Data/DbSeeder.cs, SeedAsync, константа Lab05Marker та initializer IncidentComment з Id 30000000-0000-0000-0000-000000000005 (автор Morgan). У продукті джерелом був би будь-який автор коментаря	Text = Lab05Marker	синтетичний seed; у продукті — контрольоване користувачем
Request	окремого create endpoint для коментарів немає; читання: GET /api/incidents/20000000-0000-0000-0000-000000000001 (body відсутнє; Guid обирає запис)	—	у request нового тексту немає
Validation/mapping	Application/Incidents/IncidentQueries.cs, GetDetailsAsync: проєкція incident.Comments.Where(includeInternal || !IsInternal) → IncidentCommentResponse	comment.Text → Text	internal-коментарі фільтруються за правом читання (ЛР4), вміст не очищується; видимість ≠ безпека відображення
Storage	Data/Entities/IncidentComment.cs → Text; колонка text, HasMaxLength(2000)	дослівний marker	збережене значення користувача
Response	Presentation/Contracts/IncidentResponses.cs, IncidentCommentResponse.Text; JSON-поле comments[].text	comments[].text	недовірене для відображення
Client transform	browser-lab.js, load(): цикл for (const comment of current.comments ?? []), створення <p>	comment.text	перетворень немає
Sink/context	browser-lab.js, цикл у load(): paragraph.innerHTML = comment.text;	HTML-рядок → HTML-парсер	vulnerable: HTML-контекст. Fixed: renderText(paragraph, comment.text) → textContent
3. Інвентаризація DOM sink-ів і джерел даних

Межа: власний код клієнта в src/SecureLab.Api/Client/. Пошук: innerHTML, outerHTML, insertAdjacentHTML, inline-обробники, eval, new Function, динамічні URL.

Місце	Дані, що потрапляють у sink	Категорія даних	Контекст	Рішення
browser-lab.js load() → #description (innerHTML)	current.description	збережене значення користувача	HTML parser	небезпечно → замінити на textContent (через renderText)
browser-lab.js load() → #comments p (innerHTML)	comment.text	збережене значення користувача	HTML parser	небезпечно → замінити на textContent (через renderText)
browser-lab.js load() → #title	current.title	збережене значення користувача	text node (textContent)	уже безпечно, лишити
browser-lab.js load() → #status	`GET: ${response.status}`	server-generated (число)	text node (textContent)	безпечно
browser-lab.js → поле форми elements.description.value	current.description	збережене значення користувача	значення form control (.value)	безпечно: значення не парситься як HTML
Client/app.js (список/details головної сторінки)	title, status, автор, текст	збережене значення користувача / server-generated	text node через createTextElement	безпечно (textContent); innerHTML у файлі немає
auth-lab.js, session-flow.js	статуси та повідомлення входу	server-generated	text node	innerHTML немає; перевірено пошуком
Dynamic URL (href/src з даних), inline handlers, eval, new Function	—	—	URL / code	у власному коді клієнта не знайдено; якщо посилання з даних знадобляться — окрема policy https:/http: через new URL()

Перевірка інвентаризації:

grep -rn "innerHTML\|outerHTML\|insertAdjacentHTML\|eval(\|new Function" src/SecureLab.Api/Client/

До fix очікуються рівно два збіги, обидва в browser-lab.js; після fix — жодного.

4. Підсумок до → причина → fix → retest → залишковий ризик
Етап	Опис
До	marker у description і в comments[].text перетворюється innerHTML на <img onerror>; виконується в сеансі Morgan (Analyst); #lab05-marker-target отримує data-lab05-marker="executed"
Першопричина	недовірений рядок потрапляє в HTML-sink (innerHTML) замість текстового вузла; не відсутність фільтра слова script
Fix	у browser-lab.js обидва місця виведення через renderText(element, value) → element.textContent; структура елементів створюється кодом (createElement), дані — лише текстом. Сервер і БД не змінювались
Retest	той самий marker і той самий запис: в #description один текстовий вузол, елемента <img> немає, запиту x немає, перевірка getAttribute("data-lab05-marker") → null; значення в JSON до і після збігається; legit-текст (лапки, <, >, Unicode, 4000 символів) відображається без пошкоджень
Залишковий ризик	інші поля й sink-и, яких тут не охоплено; сторонній код (Scalar на /scalar, лише Development); CSP — додатковий шар, а не заміна safe DOM

Номер першого коміту з виправленням: ⟨XSS-fix hash⟩; fixed code commit: ⟨fixed hash⟩.