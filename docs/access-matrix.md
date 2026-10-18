# Матриця контролю доступу: Incident (baseline 2-A)

Ролі: Reporter (alice, bob), Analyst (morgan), Administrator (admin).
Allow означає конкретне право на дію над конкретним ресурсом, а не лише успішний login.

## Політика відповідей

|Стан запиту|Відповідь|
|-|-|
|Немає authentication (анонім)|401 Unauthorized|
|Автентифікований, ресурс існує, але правило не виконано|403 Forbidden|
|Ідентифікатор не існує|404 Not Found|

Обґрунтування 403: інциденти не є секретом існування для автентифікованих користувачів корпоративного трекера, а явна відмова допомагає клієнту зрозуміти, що причина в правах, а не в помилці id. Політика однакова для details, update, delete, triage і child comment.

## Матриця

|Дія|Рівень|Анонім|Reporter: власник|Reporter: не власник|Analyst|Administrator|Статус відмови|
|-|-|-|-|-|-|-|-|
|Перегляд списку GET /api/incidents|добрий|deny|лише власні|лише власні|усі|лише власні (їх немає)|401 для анонім|
|Пошук GET /api/incidents/search|відмінний (A-11)|deny|лише власні|лише власні|усі|лише власні (їх немає)|401 для анонім|
|Зведення GET /api/incidents/severity-summary|відмінний (A-11)|deny|лише власні|лише власні|усі|лише власні (їх немає)|401 для анонім|
|Перегляд деталей GET /api/incidents/{id}|достатній|deny|allow|deny|allow (для аналізу)|deny|401 / 403|
|Створення POST /api/incidents|успадкований baseline|deny|allow, owner = principal|allow, owner = principal|allow, owner = principal|allow, owner = principal|401|
|Update content PUT /api/incidents/{id}|добрий|deny|allow (title, description, severity, occurredAtUtc)|deny|deny|deny|401 / 403|
|Delete DELETE /api/incidents/{id}|добрий|deny|allow, лише поки status = New|deny|deny|deny|401 / 403|
|Зміна статусу POST /api/incidents/{id}/triage (New -> Triaged)|добрий|deny|deny|deny|allow, лише з New|deny|401 / 403 / 409|
|Перегляд коментаря GET /api/incident-comments/{id}, не internal|добрий|deny|allow, лише до власного incident|deny|allow|deny|401 / 403|
|Перегляд коментаря GET /api/incident-comments/{id}, internal|добрий|deny|deny|deny|allow|deny|401 / 403|
|Export / audit|відмінний, якщо flow існує|не застосовується|не застосовується|не застосовується|не застосовується|не застосовується|у проєкті такого endpoint немає|

## Службові правила

* Id, owner, role і status ніколи не приймаються з тіла запиту. owner береться з verified principal, role з server-issued claim, наступний status встановлює сервер.
* Administrator не отримує прав "на все": для Incident йому не опубліковано жодних додаткових прав (least privilege).
* Analyst може лише читати й переводити New -> Triaged. Content він змінювати й видаляти не може.
* Відмовлена привілейована дія (triage) пише audit event authorization.denied без cookie, password, token і тіла запиту.



## Привілейована дія: POST /api/incidents/{id}/triage (New -> Triaged)

| Питання | Правило |
|---|---|
| Яка роль має право | лише Analyst (Morgan) |
| Додатковий контекст | інцидент має бути у статусі New; з іншого статусу відповідь 409. Наступний статус визначає сервер, клієнт нічого не передає |
| Чи може owner виконати transition | ні: Reporter-власник створює інцидент і змінює його зміст, але не переводить статус |
| Reporter-власник | 403 |
| Інший Reporter | 403 |
| Analyst | 200 (статус New), 409 (статус не New) |
| Administrator | 403 (не має прав на Incident) |
| Анонім / неіснуючий id | 401 / 404 |
| Audit event при відмові | `authorization.denied`: subject (id з principal), action `incident.triage`, resource `incident/{id}`, result `denied`, час сервера UTC, trace id. Без cookie, password, token і тіла запиту |

## Видимість ресурсу (відмінний рівень)

Політика 403 означає, що автентифікований користувач може дізнатися, що інцидент з таким id існує. Це свідомий і прийнятний ризик:

- id інцидентів є випадковими UUID, їх практично неможливо перебрати; водночас UUID не вважається захистом сам по собі, доступ вирішує сервер;
- відповідь 403 не містить жодних даних ресурсу й не повторює id у тексті помилки;
- факт існування інциденту не є таємницею для співробітників трекера, а чітка відмова допомагає відрізнити «немає прав» від «неправильний id»;
- ресурс недоступний без автентифікації (401), а список, пошук і підсумок обмежені тим самим правилом видимості.

Політика однакова для details, update, delete, triage і child comment. Тому рядок A-10 (нерозрізнюваність 404) не застосовується.

## Least privilege: чому ролі мають саме ці права

- **Reporter** створює інциденти й керує лише власними: цього достатньо, щоб подавати й уточнювати власні звіти. Чужі записи та internal-коментарі йому не потрібні. Видалити власний інцидент можна лише у статусі New, щоб не знищувати матеріал після початку обробки.
- **Analyst** читає всі інциденти й internal-коментарі, бо аналізує чужі звіти, і може лише перевести `New -> Triaged`. Змінювати або видаляти чужий зміст йому не потрібно, тому цих прав немає.
- **Administrator** керує обліковими записами, а не вмістом інцидентів: для домену Incident йому не надано жодних прав. Роль «admin» не означає «дозволено все», будь-яке розширення потребує окремого рішення й оновлення матриці.

Охоплені шляхи: list, search, severity-summary, details, update, delete, triage, child comment. Не охоплено, бо їх немає у проєкті: batch та export. Залишкові ризики (CSRF до ЛР 6, concurrent transition без version check) описано у звіті.
