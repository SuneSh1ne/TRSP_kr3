# Контрольная работа №3

## Команды для теста заданий:
### Задание 6.1 — Базовая HTTP-аутентификация
 Попытка без авторизации (должен вернуть 401)
curl -X GET http://127.0.0.1:8000/task6_1/secret

 С неверными данными (401)
curl -X GET http://127.0.0.1:8000/task6_1/secret -u wrong:wrong

 С верными данными (200, секретное сообщение)
curl -X GET http://127.0.0.1:8000/task6_1/secret -u admin:secret123

 Проверка заголовка WWW-Authenticate (401)
curl -v -X GET http://127.0.0.1:8000/task6_1/secret

### Задание 6.2 — Безопасная аутентификация с хешированием
 Регистрация пользователя (201)
 curl -X POST http://127.0.0.1:8000/task6_2/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test_user","password":"mypassword"}'

 Попытка повторной регистрации (400)
 curl -X POST http://127.0.0.1:8000/task6_2/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test_user","password":"another"}'

 Вход с верными данными (200)
curl -X GET http://127.0.0.1:8000/task6_2/login -u test_user:mypassword

 Вход с неверными данными (401)
curl -X GET http://127.0.0.1:8000/task6_2/login -u test_user:wrongpass

### Задание 6.4 — JWT-аутентификация
 Вход с верными данными (200, получим токен)
curl -X POST http://127.0.0.1:8000/task6_4/login \
  -H "Content-Type: application/json" \
  -d '{"username":"john_doe","password":"securepassword123"}'
 Сохрани токен в переменную
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/task6_4/login \
  -H "Content-Type: application/json" \
  -d '{"username":"john_doe","password":"securepassword123"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

echo $TOKEN

 Доступ к защищенному ресурсу с токеном (200)
curl -X GET http://127.0.0.1:8000/task6_4/protected_resource \
  -H "Authorization: Bearer $TOKEN"

 Доступ без токена (401)
curl -X GET http://127.0.0.1:8000/task6_4/protected_resource

 Вход с неверными данными (401)
curl -X POST http://127.0.0.1:8000/task6_4/login \
  -H "Content-Type: application/json" \
  -d '{"username":"john_doe","password":"wrongpassword"}'

 Вход несуществующего пользователя (401)
curl -X POST http://127.0.0.1:8000/task6_4/login \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexistent","password":"password"}'

### Задание 6.5 — JWT + регистрация + rate limiting
 Регистрация пользователя (201)
curl -X POST http://127.0.0.1:8000/task6_5/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"qwerty123"}'

 Попытка повторной регистрации (409)
curl -X POST http://127.0.0.1:8000/task6_5/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"another"}'

 Тест rate limiting на регистрацию (1 запрос/мин)
 Выполни дважды подряд - второй вернет 429
curl -X POST http://127.0.0.1:8000/task6_5/register \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","password":"test123"}'

 Вход с верными данными (200)
curl -X POST http://127.0.0.1:8000/task6_5/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"qwerty123"}'

 Сохраняем токен
TOKEN2=$(curl -s -X POST http://127.0.0.1:8000/task6_5/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"qwerty123"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

 Доступ к защищенному ресурсу (200)
curl -X GET http://127.0.0.1:8000/task6_5/protected_resource \
  -H "Authorization: Bearer $TOKEN2"

 Вход несуществующего пользователя (404)
curl -X POST http://127.0.0.1:8000/task6_5/login \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexistent","password":"password"}'

 Тест rate limiting на логин (5 запросов/мин)
 Выполни 6 раз подряд - 6-й вернет 429
for i in {1..6}; do
  curl -X POST http://127.0.0.1:8000/task6_5/login \
    -H "Content-Type: application/json" \
    -d '{"username":"alice","password":"wrongpass"}'
  echo "Request $i"
done

### Задание 7.1 — RBAC
 Регистрируем пользователей с разными ролями
 Администратор
curl -X POST "http://127.0.0.1:8000/task7_1/register?role=admin" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin_user","password":"admin123"}'

 Обычный пользователь
curl -X POST "http://127.0.0.1:8000/task7_1/register?role=user" \
  -H "Content-Type: application/json" \
  -d '{"username":"normal_user","password":"user123"}'

 Гость
curl -X POST "http://127.0.0.1:8000/task7_1/register?role=guest" \
  -H "Content-Type: application/json" \
  -d '{"username":"guest_user","password":"guest123"}'

 Получаем токены для каждого
ADMIN_TOKEN=$(curl -s -X POST http://127.0.0.1:8000/task7_1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin_user","password":"admin123"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

USER_TOKEN=$(curl -s -X POST http://127.0.0.1:8000/task7_1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"normal_user","password":"user123"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

GUEST_TOKEN=$(curl -s -X POST http://127.0.0.1:8000/task7_1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"guest_user","password":"guest123"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

 Админ создает ресурс (201)
curl -X POST http://127.0.0.1:8000/task7_1/resources \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Secret Data","data":"Top secret information"}'

 Пользователь пытается создать ресурс (403)
curl -X POST http://127.0.0.1:8000/task7_1/resources \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My Data","data":"My information"}'

 Все могут читать ресурсы (200)
curl -X GET http://127.0.0.1:8000/task7_1/resources \
  -H "Authorization: Bearer $GUEST_TOKEN"

 Пользователь обновляет ресурс (200)
curl -X PUT http://127.0.0.1:8000/task7_1/resources/1 \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Updated Data","data":"Updated information"}'

 Гость пытается обновить (403)
curl -X PUT http://127.0.0.1:8000/task7_1/resources/1 \
  -H "Authorization: Bearer $GUEST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Hacked Data"}'

 Гость пытается удалить (403)
curl -X DELETE http://127.0.0.1:8000/task7_1/resources/1 \
  -H "Authorization: Bearer $GUEST_TOKEN"

 Админ удаляет ресурс (200)
curl -X DELETE http://127.0.0.1:8000/task7_1/resources/1 \
  -H "Authorization: Bearer $ADMIN_TOKEN"

 Доступ к защищенному ресурсу (admin/user - 200, guest - 403)
curl -X GET http://127.0.0.1:8000/task7_1/protected_resource \
  -H "Authorization: Bearer $ADMIN_TOKEN"

curl -X GET http://127.0.0.1:8000/task7_1/protected_resource \
  -H "Authorization: Bearer $GUEST_TOKEN"

### Задание 8.1 — Регистрация в SQLite
 Регистрация пользователя (200)
curl -X POST http://127.0.0.1:8000/task8_1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test_user","password":"12345"}'

 Регистрация другого пользователя (200)
curl -X POST http://127.0.0.1:8000/task8_1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"another_user","password":"password"}'

 Попытка зарегистрировать существующего пользователя (409)
curl -X POST http://127.0.0.1:8000/task8_1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test_user","password":"newpassword"}'

 Проверка данных в БД (должна быть в файле app.db)
sqlite3 app.db "SELECT * FROM users;"

### Задание 8.2 — CRUD Todo
 Создание Todo (201)
curl -X POST http://127.0.0.1:8000/task8_2/todos \
  -H "Content-Type: application/json" \
  -d '{"title":"Buy groceries","description":"Milk, eggs, bread"}'

 Создание еще одного Todo
curl -X POST http://127.0.0.1:8000/task8_2/todos \
  -H "Content-Type: application/json" \
  -d '{"title":"Study","description":"Read FastAPI docs"}'

 Получение Todo по ID (200)
curl -X GET http://127.0.0.1:8000/task8_2/todos/1

 Получение несуществующего Todo (404)
curl -X GET http://127.0.0.1:8000/task8_2/todos/999

 Обновление Todo (200)
curl -X PUT http://127.0.0.1:8000/task8_2/todos/1 \
  -H "Content-Type: application/json" \
  -d '{"title":"Buy food","completed":true}'

 Обновление несуществующего Todo (404)
curl -X PUT http://127.0.0.1:8000/task8_2/todos/999 \
  -H "Content-Type: application/json" \
  -d '{"title":"Nothing"}'

 Удаление Todo (200)
curl -X DELETE http://127.0.0.1:8000/task8_2/todos/2

 Удаление несуществующего Todo (404)
curl -X DELETE http://127.0.0.1:8000/task8_2/todos/999

 Проверка данных в БД
sqlite3 app.db "SELECT * FROM todos;"