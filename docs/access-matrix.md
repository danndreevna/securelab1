# Матриця контролю доступу: Incident (baseline 2-A)

Ролі: Reporter (alice, bob), Analyst (morgan), Administrator (admin).
Allow означає конкретне право на дію над конкретним ресурсом, а не лише успішний login.

## Політика відповідей

| Стан запиту | Відповідь |
|---|---|
| Немає authentication (анонім) | 401 Unauthorized |
| Автентифікований, ресурс існує, але правило не виконано | 403 Forbidden |
| Ідентифікатор не існує | 404 Not Found |

Обґрунтування 403: інциденти не є секретом існування для автентифікованих користувачів корпоративного трекера, а явна відмова допомагає клієнту зрозуміти, що причина в правах, а не в помилці id. Політика однакова для details, update, delete, triage і child comment.

## Матриця

| Дія | Рівень | Анонім | Reporter: власник | Reporter: не власник | Analyst | Administrator | Статус відмови |
|---|---|---|---|---|---|---|---|
| Перегляд списку GET /api/incidents | добрий | deny | лише власні | лише власні | усі | лише власні (їх немає) | 401 для анонім |
| Пошук GET /api/incidents/search | відмінний (A-11) | deny | лише власні | лише власні | усі | лише власні (їх немає) | 401 для анонім |
| Зведення GET /api/incidents/severity-summary | відмінний (A-11) | deny | лише власні | лише власні | усі | лише власні (їх немає) | 401 для анонім |
| Перегляд деталей GET /api/incidents/{id} | достатній | deny | allow | deny | allow (для аналізу) | deny | 401 / 403 |
| Створення POST /api/incidents | успадкований baseline | deny | allow, owner = principal | allow, owner = principal | allow, owner = principal | allow, owner = principal | 401 |
| Update content PUT /api/incidents/{id} | добрий | deny | allow (title, description, severity, occurredAtUtc) | deny | deny | deny | 401 / 403 |
| Delete DELETE /api/incidents/{id} | добрий | deny | allow, лише поки status = New | deny | deny | deny | 401 / 403 |
| Зміна статусу POST /api/incidents/{id}/triage (New -> Triaged) | добрий | deny | deny | deny | allow, лише з New | deny | 401 / 403 / 409 |
| Перегляд коментаря GET /api/incident-comments/{id}, не internal | добрий | deny | allow, лише до власного incident | deny | allow | deny | 401 / 403 |
| Перегляд коментаря GET /api/incident-comments/{id}, internal | добрий | deny | deny | deny | allow | deny | 401 / 403 |
| Export / audit | відмінний, якщо flow існує | не застосовується | не застосовується | не застосовується | не застосовується | не застосовується | у проєкті такого endpoint немає |

## Службові правила

- Id, owner, role і status ніколи не приймаються з тіла запиту. owner береться з verified principal, role з server-issued claim, наступний status встановлює сервер.
- Administrator не отримує прав "на все": для Incident йому не опубліковано жодних додаткових прав (least privilege).
- Analyst може лише читати й переводити New -> Triaged. Content він змінювати й видаляти не може.
- Відмовлена привілейована дія (triage) пише audit event authorization.denied без cookie, password, token і тіла запиту.