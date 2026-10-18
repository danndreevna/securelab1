# Звіт з лабораторної роботи 4. Авторизація, ролі, володіння ресурсом та IDOR/BOLA

| | |
|---|---|
| Студентка | Дар'я Курмишкіна, група КБ-43 |
| Курс | Прикладні технології програмування в інформаційній безпеці |
| Викладач | Бабенко Юрій Михайлович |
| Baseline / рівень | 2-A / відмінний |
| Гілка | `lab/4-authorization` |
| Тег | `v0.4.0` (на fixed commit) |

## 1. Хеші станів

| Стан | Commit | Повний hash |
|---|---|---|
| Початок ЛР 4 (результат ЛР 3) | `35eb379` | тег `v0.3.0` |
| Матриця доступу | `317d267` | |
| Seed: internal comment | `e5f3be4` | |
| **Vulnerable state** (докази дефекту) | `d5d7760` | `d5d776009236852afddff09173bba3d2f1f435fd` |
| **Fixed state** (код, тести, `.http`) | `83a67aa` | `83a67aaafb1bd6eb938ab26da2845d690c800573` |
| Тег `v0.4.0` вказує на | `83a67aa` | `git rev-parse "v0.4.0^{commit}"` дає той самий hash |

Vulnerable state (`d5d7760`) зберігається лише в локальному приватному репозиторії навчального проєкту, не публікується у відкритий remote і не використовується для deployment. Тег не ставився на vulnerable commit. Історію не переписувано. Hash цього звіту не можна вписати в його власний commit, тому звіт додано окремим commit «Record lab 4 hashes» після тегу.

## 2. Параметри роботи

- Головний ресурс: `Incident`. Дочірній: `IncidentComment` через `GET /api/incident-comments/{id}`. Привілейована дія: `POST /api/incidents/{id}/triage`, перехід `New → Triaged` для Analyst (Morgan).
- Суб'єкти (seed): alice і bob (Reporter), morgan (Analyst), admin (Administrator). Роль потрапляє в cookie під час login.
- Обрана політика для чужого ресурсу: **403** (ресурс існує, але правило не виконано). Неіснуючий id дає 404, анонім дає 401. Обґрунтування наведено в `docs/access-matrix.md`.
- Owner, role, status та id визначає сервер. Клієнтський DTO оновлення (`UpdateIncidentRequest`) містить лише title, description, severity, occurredAtUtc.
- Обрано альтернативу A-08a (невідоме поле ігнорується). A-08b не виконувалась.

## 3. Доказова таблиця

Усі «Фактично» отримані мною на локальному стенді: автоматичними тестами (`dotnet test`), PowerShell-запитами з cookie-сесією та в браузері (DevTools, `loadIncidentDetails`). Скриншоти не містять паролів, cookie, токенів і рядків підключення.

| ID | Рівень | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|---|
| A-01 | добрий | Анонімний доступ | немає authentication context | 8 запитів без входу: GET list, search, severity-summary, details, PUT, DELETE, POST triage, GET comment | 401, не HTML redirect | 401 на всіх 8 маршрутах, заголовка `Location` немає | `A01_Anonymous_ProtectedEndpoints_Return401NotRedirect` (8 випадків) |
| A-02 | достатній, обов'язковий | Власний ресурс | Alice, її seed-інцидент `...0001`; новий власний інцидент | GET details; PUT; DELETE власного New | allow | GET 200 (внутрішнього коментаря немає); PUT 204, змінились лише дозволені поля, owner і status ті самі; DELETE 204, подальший GET 404 | `A02_Details_AsOwner...`, `A02_Update_AsOwner...`, `A02_Delete_AsOwnerWhileNew...` |
| A-03 | достатній, обов'язковий | Чужий ресурс | Alice, інцидент Bob `...0002` | GET `/api/incidents/{id Bob}` | 403 | **до:** 200 з даними Bob; **після:** 403, тіло без description, ownerDisplayName, comments. У браузері той самий запит дав 403. Bob → інцидент Alice теж 403. Administrator 403. Неіснуючий id дає 404 | `A03_*` (4 тести), PowerShell, DevTools Network (403) |
| A-03R | достатній, entry-контракт ЛР 5 | Дозволений аналітичний read | Morgan (Analyst) | GET details інцидентів Alice і Bob | allow для аналізу | 200 для обох. Права довільної mutation це не дає (див. A-07) | `A03R_Details_AsAnalyst...` |
| A-04 | добрий | Чужий ресурс, усі змінювальні дії | Alice, Bob resource | PUT і DELETE інциденту Bob; DELETE власного не-New | deny, state без змін | 403 для всіх трьох. JSON деталей Bob до і після ідентичний | `A04_Update_AsNonOwner...`, `A04_Delete_AsNonOwner...`, `A04_Delete_OwnIncidentThatIsNotNew...` |
| A-05 | добрий | List | Alice | GET `/api/incidents` | лише дозволена множина | **до:** 5 інцидентів, серед них чужі; **після:** 3 власні (`...0001`, `...0003`, `...0005`), інцидентів Bob немає. Analyst бачить усі | `A05_List_AsReporter...`, `A05_List_AsAnalyst...`, PowerShell |
| A-06 | добрий | Вертикальне підвищення привілеїв | Reporter-owner, інший Reporter, Administrator; новий інцидент (New) | POST `/triage` | deny, status без змін | 403 для всіх трьох, статус після читання власником: `New` | `A06_Triage_AsReporterOwner...`, `..._AsOtherReporter...`, `..._AsAdministrator...` |
| A-07 | добрий | Дозволена привілейована дія | Morgan (Analyst), інцидент у стані New | POST `/triage`; повтор; PUT і DELETE чужого | allow; роль не дає зайвих прав | перший виклик 200, статус `Triaged`; повторний виклик 409; PUT і DELETE від Analyst 403, стан без змін | `A07_Triage_AsAnalyst...`, `A07_Update_AsAnalyst...` |
| A-08a | добрий, альтернатива A-08b | Overposting: невідоме поле ігнорується | Alice, власний інцидент | PUT із додатковими `ownerUserId` (Bob), `role` (Administrator), `status` (Resolved), `isTransitionAllowed` | заздалегідь визначений success status 204; protected state не змінюється | 204; title змінився; у БД `OwnerUserId` = Alice, `Status` = New | `A08a_Update_WithForgedOwnerRoleAndStatus...` (перевірка через БД) |
| A-08b | добрий, альтернатива A-08a | Контракт відхиляє зайве поле | | | | не виконувалось: обрано A-08a | |
| A-09 | добрий | Audit event | denied privileged request (Alice, triage) | знайти `authorization.denied` у виводі API | безпечна подія без секретів, той самий trace id | подія містить `subject` (id Alice), `action=incident.triage`, `resource=incident/{id}`, `result=denied`, час сервера UTC, `trace=`; trace збігається з `traceId` у відповіді клієнту. Паролів і cookie немає | `A09_DeniedTriage_WritesAuditEventWithSameTraceId...`, рядок із логу (скриншот) |
| A-10 | добрий, лише політика 404 | Нерозрізнюваність 404 | | | | не застосовується: обрано політику 403 (`docs/access-matrix.md`, «Політика відповідей»). Перевірка A-03 цим не підмінена | |
| A-11 | відмінний | Власні endpoint-и ЛР 1-2 | Alice; відомий seed | `GET /api/incidents/search?q=Brien`; `GET /api/incidents/severity-summary` | лише дозволена множина | **до:** пошук повертає інцидент Bob `...0004` (навіть анонімно, 200); підсумок `Low 3, High 1, Medium 1`. **після:** пошук `[]` (401 для анонімного); підсумок `Low 2, Medium 1` | `A11_Search_AsReporter...`, `A11_SeveritySummary_AsReporter...`, PowerShell до/після |
| A-12 | добрий | Child resource та internal comment | Alice; коментар `...0002` під інцидентом Bob; internal comment `...0003` під інцидентом Alice | GET `/api/incident-comments/{id}` | child access: deny за політикою; internal не потрапляє Reporter | коментар під чужим інцидентом: 403; internal comment для Alice (власниця інциденту): 403; публічний коментар власного інциденту: 200; internal для Morgan: 200; неіснуючий коментар: 404; details для Alice не містять internal comment | `A12_*` (4 тести) |

Підсумок автоматичних перевірок: усього 50 тестів (34 нових у `IncidentAuthorizationTests`, решта з ЛР 1-3, у тому числі адаптовані до входу `IncidentEndpointTests` і `SearchMechanicsTests`). Після повного відновлення бази (`--reset-database`) запуск у конфігурації Release: `failed: 0; succeeded: 50`.

## 4. Основний finding: BOLA/IDOR на інциденті

**1. Контекст.** Ресурс: `Incident`. Дії: читання деталей, зміна, видалення, перехід статусу, читання дочірнього коментаря. Локальні суб'єкти: alice, bob (Reporter), morgan (Analyst), admin (Administrator).

**2. Гіпотеза.** Автентифікована Alice зможе прочитати інцидент Bob, підставивши його id (`20000000-0000-0000-0000-000000000002`) у маршрут, бо сервер перевіряє лише наявність входу.

**3. Стан до** (vulnerable commit `d5d776009236852afddff09173bba3d2f1f435fd`). Alice після входу: `GET /api/incidents/...0002` повертає `200` з назвою, описом, статусом і коментарем Bob; `GET /api/incidents` повертає 5 інцидентів, серед них чужі. Додатково пошук `search?q=Brien` повертає інцидент Bob навіть анонімно, а severity-summary для Alice рахує всі 5 інцидентів (`Low 3, High 1, Medium 1`).

**4. Першопричина.** Data-access шлях `IncidentQueries.GetDetailsAsync` вибирав запис лише за `incident.Id == id`, без умови власника й без перевірки ролі. `GetListAsync`, пошук і severity-summary не мали звуження за суб'єктом. Маршрут пошуку був взагалі без `RequireAuthorization`, а група `/api/incidents` вимагала лише автентифікацію без рішення щодо ресурсу. Додаткового endpoint для дочірніх коментарів, update, delete і transition не існувало.

**5. Виправлення** (fixed commit `83a67aaafb1bd6eb938ab26da2845d690c800573`).
- Група `/api/incidents` і новий `GET /api/incident-comments/{id}` отримали `.RequireAuthorization()` (401 для анонімного).
- Resource-based authorization: `IncidentAuthorizationHandler` з операціями `Read`, `Update`, `Delete`, `Triage` (`IncidentOperations`). Правила: Read = власник або Analyst; Update = власник; Delete = власник і статус New; Triage = Analyst. Суб'єкт береться лише з перевіреного principal (`NameIdentifier`, `IsInRole`), ніколи із запиту.
- Query scoping (`IncidentScope.VisibleTo`): список, пошук і severity-summary звужуються за суб'єктом **до** `OrderBy`/`Take(50)`/групування, а не фільтруються в пам'яті.
- Порядок для змін: завантаження tracked entity, рішення про операцію, при deny audit і відмова 403, перевірка допустимості поточного статусу (409), сервер визначає наступний статус, `SaveChangesAsync`.
- Межі DTO: `UpdateIncidentRequest` не містить owner, role, status. Для transition клієнт нічого не передає, перехід фіксований `New → Triaged`.
- Child resource: коментар перевіряється через батьківський інцидент (`Read`) і додатково за `IsInternal` (лише Analyst).
- Audit: подія `authorization.denied` (subject, action, resource, result, час сервера, trace id), без cookie, пароля, токена та тіла запиту. `traceId` у відповіді 403 збігається з `trace` в audit-події.
- Відповіді 403 і 404 не містять `detail` з id ресурсу.

**6. Retest.** Той самий запит Alice → `...0002` після виправлення: `403`, даних Bob немає (PowerShell, браузер і автотест). Mutation (PUT, DELETE, triage) від Alice над ресурсом Bob: `403`, стан ресурсу до і після ідентичний.

**7. Позитивна регресія.** Alice читає, змінює і видаляє (поки New) власний інцидент; Morgan читає інциденти для аналізу й виконує `New → Triaged`; повторний transition дає 409; Analyst не може змінити чужий content.

**8. Залишковий ризик.**
- **CSRF** для cookie-authenticated mutating endpoints (PUT, DELETE, POST triage): `SameSite=Lax` зменшує, але не усуває ризик; повноцінний захист до ЛР 6 лишається явно документованим навчальним боргом ЛР 3.
- Політика 403 розкриває факт існування чужого інциденту автентифікованому користувачу (свідомий вибір, пояснений у матриці).
- Concurrent transition: два одночасні запити triage теоретично можуть обидва пройти перевірку `Status == New` до збереження, бо concurrency token не застосовано.
- Роль зчитується з cookie, виданого при login: після зміни ролі користувач має увійти повторно (або відкликати сесії).
- Audit-події пишуться лише у структурований лог застосунку, без постійного сховища і сповіщень.
- Batch або непрямі endpoint-и, окрім перевіреного child comment, у поточному стані проєкту відсутні, тому не покриті.
- Administrator не має прав на інциденти за принципом least privilege (відображено в матриці). Бізнес-вимоги, що змінюють це, потребують окремого рішення.

**Схема рішення.**
Запит Alice з id → cookie формує перевірений principal → завантаження ресурсу (для списків: обмежений за суб'єктом запит) → правило owner / role / status у `IncidentAuthorizationHandler` → дозвіл або погоджена відмова 403 (неіснуючий id: 404, анонім: 401) → відповідь. Змінювальна дія виконується лише після дозволу.

## 5. Додатковий finding (відмінний рівень): A-11, search і severity-summary

- **Стан до:** `GET /api/incidents/search?q=Brien` повертав інцидент Bob `...0004` (200) навіть без автентифікації, оскільки маршрут не мав `RequireAuthorization`. `GET /api/incidents/severity-summary` для Alice повертав агрегати за всіма 5 інцидентами: `Low 3, High 1, Medium 1`, тобто розкривав наявність чужих записів через статистику.
- **Першопричина:** запити будувались над `dbContext.Incidents` без умови суб'єкта; захист існував лише у вигляді відсутнього або загального рішення.
- **Виправлення:** маршрут пошуку отримав `RequireAuthorization`. Обидва запити використовують один механізм `VisibleTo(viewer)` у самому запиті до БД: у search до фільтра, сортування й `Take(50)`, у severity-summary до `GroupBy`. Записи не завантажуються, щоб відфільтрувати їх у пам'яті.
- **Retest:** Alice: search повертає `[]`, підсумок `Low 2, Medium 1`; анонімний запит дає 401. Автоматичні перевірки: `A11_*`.
- **Least privilege і видимість.** Analyst бачить агрегати за всіма інцидентами (потрібно для аналізу); Reporter і Administrator бачать лише власні. Залишкові ризики розширеного охоплення: агрегована статистика Analyst охоплює всі записи (це відображено в матриці), а пошук за вільним текстом по чужих записах Reporter взагалі недоступний.

## 6. Перевірка (відновлення стану та прогін)

```text
docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
dotnet run --project src/SecureLab.Api -- --reset-database
dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release
dotnet run --project src/SecureLab.Api --launch-profile http
```

Результат тестів: `total: 50; failed: 0; succeeded: 50`. Потім виконано ручний ретест на чистих даних і перевірку в браузері: вхід alice через `auth-lab.html`, головна сторінка завантажує список з API (для Alice це її 3 інциденти), клік по власному інциденту показує його деталі (200). Виклик `loadIncidentDetails("20000000-0000-0000-0000-000000000002")` повертає `403`, клієнт виводить title відповіді через `textContent`. Клієнт (`app.js`) використовує `createTextElement` і `textContent`, а не `innerHTML`; він лише відображає рішення сервера, server-side авторизацію не замінює. Файл `tests/http/lab-04-access.http` описує сценарії доступу з паролем-заглушкою (пароль у Git не зберігається); фактично їх виконано PowerShell-запитами та автотестами.

Примітка щодо даних: тести ЛР 3 (`AuthorizationRegressionTests`) створюють інциденти Bob без видалення, тому після повного прогону в базі можуть бути додаткові записи Bob. Нові тести ЛР 4 працюють лише зі створеними ними ж інцидентами й видаляють їх після завершення, тож результат для Alice (3 інциденти, `Low 2, Medium 1`) від цього не залежить.

## 7. Перелік змін

| Файл | Зміна |
|---|---|
| `docs/access-matrix.md` | матриця доступу, політика 401/403/404 |
| `src/SecureLab.Api/Data/DbSeeder.cs` | internal comment `...0003` для перевірки A-12 |
| `src/SecureLab.Api/Application/Incidents/IncidentOperations.cs` | операції Read, Update, Delete, Triage |
| `src/SecureLab.Api/Application/Incidents/IncidentAuthorizationHandler.cs` | правила owner / role / status |
| `src/SecureLab.Api/Application/Incidents/IncidentAccess.cs` | `IncidentViewer` і `VisibleTo` (query scoping) |
| `src/SecureLab.Api/Application/Incidents/IncidentQueries.cs` | звуження списку й підсумку, завантаження ресурсу, internal comments лише Analyst |
| `src/SecureLab.Api/Presentation/Endpoints/IncidentEndpoints.cs` | авторизація групи, PUT, DELETE, triage, child comment, audit |
| `src/SecureLab.Api/Presentation/Contracts/UpdateIncidentRequest.cs` | DTO без owner, role, status |
| `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs` | пошук: `RequireAuthorization` і scoping |
| `src/SecureLab.Api/Program.cs` | реєстрація handler |
| `tests/SecureLab.Api.Tests/*` | `AccessFixture`, `CapturingLoggerProvider`, `IncidentAuthorizationTests`, адаптовані `IncidentEndpointTests`, `SearchMechanicsTests`, `SecureLabApiFactory` |
| `tests/http/lab-04-access.http` | сценарії доступу |

## 8. Використання генеративного ШІ

Під час роботи використано генеративний ШІ (Claude, Anthropic) як помічник: пояснення теорії з методички, чернетки коду handler, запитів, тестів і цього звіту. Усі зміни я вносила в проєкт власноруч, перевіряла збіркою, автотестами (50/50 у Release після відновлення бази), ручними запитами з окремими cookie-сесіями та в браузері, а також звіряла результати з очікуваннями матриці доступу. Політику відповідей (403), набір правил Read / Update / Delete / Triage і вибір A-08a я підтвердила відповідно до методички й власного розуміння сценарію; рішення вмію пояснити на захисті.
