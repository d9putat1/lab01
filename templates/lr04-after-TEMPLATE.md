# Докази «після» (fixed commit ⟦hash F2⟧)

Правила ті самі: без паролів, cookie, Set-Cookie.

## A-03 · alice → інцидент Bob (до і після поруч)
- До (vulnerable): ⟦200 + дані Bob⟧ (запис B-05)
- Після (fixed): ⟦404; title «Інцидент не знайдено»; даних Bob немає⟧

## A-04 · alice → PUT/DELETE чужого
- PUT: ⟦статус⟧; DELETE: ⟦статус⟧
- Стан Bob до: ⟦…⟧; після: ⟦…⟧ (збігається ⟦так/ні⟧)

## A-06 · alice (Reporter) → triage власного New-інциденту
- Статус: ⟦403⟧; status до: ⟦New⟧; після: ⟦New⟧

## A-07 · morgan → triage New
- Статус: ⟦200⟧; status після: ⟦Triaged⟧; повторний triage: ⟦409⟧

## A-08a · forged severity/status/owner/role/isTransitionAllowed у звичайному update
- Статус: ⟦200⟧; змінилось: ⟦title/description⟧; не змінилось: ⟦severity, status, owner⟧ (psql до/після)

## A-09 · audit-подія
Рядок із терміналу API (без секретів):
```
⟦вставити рядок authorization.denied …⟧
```
Тіло відповіді 403 (traceId):
```
⟦{"type":…,"title":"Forbidden","status":403,"traceId":"…"}⟧
```
Збіг traceId: ⟦так/ні⟧

## A-10 · чужий і неіснуючий id (дві відповіді)
GET /api/incidents/{bob}:
```
⟦тіло⟧
```
GET /api/incidents/{unknown}:
```
⟦тіло⟧
```
Збігаються status, Content-Type і тіло, крім traceId: ⟦так/ні⟧

## A-11 · search і severity-summary
- анонім search/summary: ⟦401/401⟧
- alice search O'Brien: ⟦[]⟧; alice summary: ⟦Critical 0, High 0, Medium 1, Low 2⟧
- morgan summary: ⟦High 1, Medium 1, Low 3⟧; bob search O'Brien: ⟦містить …0004⟧
- SQL (search, Alice), 1–2 рядки: умова за owner_user_id до ORDER BY / LIMIT:
```
⟦вставити з логу API⟧
```

## A-12 · child і internal comment
- alice → comment-2: ⟦404⟧; alice → internal comment-3: ⟦404⟧
- details Alice, comments: ⟦лише comment-1⟧
- morgan → internal comment-3: ⟦200⟧; details Alice для Morgan: ⟦comment-1 і comment-3⟧

## A-05 · list + SQL
- alice list: ⟦…0001, …0003, …0005⟧
- SQL GET /api/incidents (Alice): лише поля DTO і WHERE за owner_user_id:
```
⟦вставити 1–2 рядки⟧
```

## Least privilege
- admin → чужий інцидент: ⟦404⟧; admin list: ⟦[]⟧
