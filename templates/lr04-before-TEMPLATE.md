# Докази «до» (vulnerable commit 239a670…; знято з окремого worktree)

Правила: кожен запис має ID, суб'єкта, очікування за матрицею, ФАКТИЧНИЙ статус і ключ тіла. Без паролів, cookie, Set-Cookie. Відповіді login не копіювати.

## B-01 · анонім · GET /api/incidents/{bobId}
- Очікування за матрицею: deny, 401
- Фактично (vulnerable): ⟦статус⟧
- Тіло (скорочено): ⟦…⟧

## B-02 · анонім · GET /api/incidents/search?q=O'Brien
- Очікування: deny, 401
- Фактично: ⟦статус; id інцидентів у відповіді⟧

## B-03 · анонім · GET /api/incidents/severity-summary
- Очікування: deny, 401
- Фактично: ⟦статус; Critical/High/Medium/Low⟧

## B-04 · alice → власний …0001 · GET details
- Очікування: allow, 200
- Фактично: ⟦статус⟧

## B-05 · alice → інцидент Bob …0002 · GET details
- Очікування: deny, 404
- Фактично: ⟦статус⟧
- Тіло (скорочено): ⟦id, title, ownerDisplayName⟧

## B-06 · alice · GET /api/incidents
- Очікування: лише власні (…0001, …0003, …0005)
- Фактично: ⟦перелік id⟧

## B-07 · alice · GET /search?q=O'Brien
- Очікування: [] (чужий інцидент не видно)
- Фактично: ⟦id у відповіді⟧

## B-08 · alice · GET /severity-summary
- Очікування: лише власні (Medium 1, Low 2)
- Фактично: ⟦Critical/High/Medium/Low⟧

## B-09 · alice → comment-2 (до інциденту Bob)
- Очікування: deny, 404
- Фактично: ⟦статус⟧

## B-10 · alice → internal comment-3 (до свого інциденту)
- Очікування: deny, 404
- Фактично: ⟦статус; чи видно текст «Внутрішня нотатка…»⟧

## B-11 · alice → PUT інциденту Bob …0004
- Очікування: deny, стан без змін
- Стан до: ⟦GET або psql: title⟧
- Статус зміни: ⟦…⟧
- Стан після: ⟦title⟧

## B-12 · alice → DELETE інциденту Bob …0004
- Очікування: deny, ресурс існує
- Статус DELETE: ⟦…⟧; GET після: ⟦…⟧

## B-13 · alice (Reporter) → triage власного …0003
- Очікування: deny (403), status без змін
- Статус: ⟦…⟧; status до: ⟦New⟧; після: ⟦…⟧

## B-14 · alice → PUT власного …0001 з forged severity/status/owner
- Очікування: змінюється лише content
- Стан до (psql): ⟦severity | status | owner⟧
- Статус: ⟦…⟧
- Стан після (psql): ⟦severity | status | owner | descr⟧
- Примітка: role та isTransitionAllowed ефекту не мали (у vulnerable DTO таких властивостей немає)

## B-15 · bob → інцидент Alice …0003
- Очікування: deny, 404
- Фактично: ⟦статус⟧
