from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPAuthorizationCredentials, HTTPBearer
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv
import os
import secrets
from typing import List

from models.task_6_2 import UserBase, User, UserInDB
from models.task_6_5 import UserRegister, UserLogin, TokenResponse, MessageResponse
from models.task_7_1 import UserRole, ResourceCreate, ResourceUpdate, ResourceResponse
from models.task_8_2 import TodoCreate, TodoUpdate, TodoResponse

from utils.auth_utils import (
    hash_password, verify_password, create_access_token,
    decode_access_token, constant_time_compare
)
from utils.database import get_db_connection, init_db

load_dotenv()

app = FastAPI(
    title="Контрольная работа №3",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

init_db()

fake_users_db: dict[str, str] = {}
secure_users_db: dict[str, str] = {}
roles_db: dict[str, UserRole] = {}
resources_db: dict[int, dict] = {}
resource_id_counter = 0

security_basic = HTTPBasic()

@app.get("/task6_1/secret", tags=["Задание 6.1"])
def basic_auth(credentials: HTTPBasicCredentials = Depends(security_basic)):
    correct_username = "admin"
    correct_password = "secret123"

    is_correct_username = secrets.compare_digest(credentials.username, correct_username)
    is_correct_password = secrets.compare_digest(credentials.password, correct_password)

    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"}
        )

    return {"message": "You got my secret, welcome"}


security_basic_6_2 = HTTPBasic()

def verify_user_from_basic(credentials: HTTPBasicCredentials = Depends(security_basic_6_2)):
    username = credentials.username
    password = credentials.password

    if username not in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"}
        )

    if not verify_password(password, fake_users_db[username]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"}
        )

    return username


@app.post("/task6_2/register", tags=["Задание 6.2"], response_model=UserInDB)
def task6_2_register(user: User):
    if user.username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists"
        )

    hashed = hash_password(user.password)
    fake_users_db[user.username] = hashed

    return UserInDB(username=user.username, hashed_password=hashed)


@app.get("/task6_2/login", tags=["Задание 6.2"])
def task6_2_login(username: str = Depends(verify_user_from_basic)):
    return {"message": f"Welcome, {username}! You got my secret, welcome"}


MODE = os.getenv("MODE", "DEV").upper()
DOCS_USER = os.getenv("DOCS_USER", "admin")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "docspass123")

if MODE not in ("DEV", "PROD"):
    raise ValueError(f"Недопустимое значение MODE: {MODE}. Допустимые: DEV, PROD")


def verify_docs_auth(request: Request):
    if MODE == "PROD":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Basic "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Basic"}
        )

    import base64
    try:
        decoded = base64.b64decode(auth[6:]).decode()
        username, password = decoded.split(":", 1)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Basic"}
        )

    if not (secrets.compare_digest(username, DOCS_USER) and
            secrets.compare_digest(password, DOCS_PASSWORD)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Basic"}
        )


@app.get("/docs", include_in_schema=False, tags=["Задание 6.3"])
async def custom_docs(request: Request):
    verify_docs_auth(request)
    return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")


@app.get("/openapi.json", include_in_schema=False, tags=["Задание 6.3"])
async def custom_openapi(request: Request):
    verify_docs_auth(request)
    return get_openapi(title="API", version="1.0.0", routes=app.routes)


@app.get("/redoc", include_in_schema=False, tags=["Задание 6.3"])
async def custom_redoc():
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


security_bearer = HTTPBearer()

task6_4_users = {
    "john_doe": "securepassword123",
    "alice": "qwerty456"
}

@app.post("/task6_4/login", tags=["Задание 6.4"])
def task6_4_login(user: UserLogin):
    if user.username not in task6_4_users:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    if user.password != task6_4_users[user.username]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    token = create_access_token(data={"sub": user.username})
    return TokenResponse(access_token=token)


@app.get("/task6_4/protected_resource", tags=["Задание 6.4"])
def task6_4_protected(credentials: HTTPAuthorizationCredentials = Depends(security_bearer)):
    token = credentials.credentials
    payload = decode_access_token(token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    return {"message": "Access granted", "user": payload.get("sub")}


@app.post("/task6_5/register", tags=["Задание 6.5"], status_code=status.HTTP_201_CREATED)
@limiter.limit("1/minute")
def task6_5_register(request: Request, user: UserRegister):
    if user.username in secure_users_db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )

    hashed = hash_password(user.password)
    secure_users_db[user.username] = hashed
    return MessageResponse(message="New user created")


@app.post("/task6_5/login", tags=["Задание 6.5"])
@limiter.limit("5/minute")
def task6_5_login(request: Request, user: UserLogin):
    found_username = None
    for u in secure_users_db:
        if constant_time_compare(u, user.username):
            found_username = u
            break

    if found_username is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if not verify_password(user.password, secure_users_db[found_username]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization failed"
        )

    token = create_access_token(data={"sub": found_username})
    return TokenResponse(access_token=token)


@app.get("/task6_5/protected_resource", tags=["Задание 6.5"])
def task6_5_protected(credentials: HTTPAuthorizationCredentials = Depends(security_bearer)):
    token = credentials.credentials
    payload = decode_access_token(token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    return MessageResponse(message="Access granted")


def get_current_user_role(credentials: HTTPAuthorizationCredentials = Depends(security_bearer)) -> UserRole:
    token = credentials.credentials
    payload = decode_access_token(token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    username = payload.get("sub")
    role = roles_db.get(username, UserRole.GUEST)
    return role


def require_role(*allowed_roles: UserRole):
    def role_checker(role: UserRole = Depends(get_current_user_role)):
        if role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role.value}' does not have permission"
            )
        return role
    return role_checker


@app.post("/task7_1/register", tags=["Задание 7.1"])
def task7_1_register(user: UserRegister, role: UserRole = UserRole.GUEST):
    if user.username in secure_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists"
        )

    hashed = hash_password(user.password)
    secure_users_db[user.username] = hashed
    roles_db[user.username] = role

    return MessageResponse(message=f"User created with role: {role.value}")


@app.post("/task7_1/login", tags=["Задание 7.1"])
def task7_1_login(user: UserLogin):
    hashed = secure_users_db.get(user.username)
    if hashed is None or not verify_password(user.password, hashed):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    role = roles_db.get(user.username, UserRole.GUEST)
    token = create_access_token(data={"sub": user.username, "role": role.value})
    return TokenResponse(access_token=token)


@app.get("/task7_1/protected_resource", tags=["Задание 7.1"])
def task7_1_protected(role: UserRole = Depends(require_role(UserRole.ADMIN, UserRole.USER))):
    return {"message": "Access granted to protected resource", "role": role.value}


@app.post("/task7_1/resources", tags=["Задание 7.1"])
def task7_1_create_resource(
    resource: ResourceCreate,
    credentials: HTTPAuthorizationCredentials = Depends(security_bearer),
    role: UserRole = Depends(require_role(UserRole.ADMIN))
):
    global resource_id_counter
    resource_id_counter += 1
    payload = decode_access_token(credentials.credentials)

    resources_db[resource_id_counter] = {
        "id": resource_id_counter,
        "name": resource.name,
        "data": resource.data,
        "owner": payload["sub"]
    }

    return ResourceResponse(**resources_db[resource_id_counter])


@app.get("/task7_1/resources", tags=["Задание 7.1"])
def task7_1_list_resources(role: UserRole = Depends(get_current_user_role)):
    return list(resources_db.values())


@app.put("/task7_1/resources/{resource_id}", tags=["Задание 7.1"])
def task7_1_update_resource(
    resource_id: int,
    resource: ResourceUpdate,
    role: UserRole = Depends(require_role(UserRole.ADMIN, UserRole.USER))
):
    if resource_id not in resources_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")

    existing = resources_db[resource_id]
    if resource.name is not None:
        existing["name"] = resource.name
    if resource.data is not None:
        existing["data"] = resource.data

    return ResourceResponse(**existing)


@app.delete("/task7_1/resources/{resource_id}", tags=["Задание 7.1"])
def task7_1_delete_resource(
    resource_id: int,
    role: UserRole = Depends(require_role(UserRole.ADMIN))
):
    if resource_id not in resources_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")

    del resources_db[resource_id]
    return MessageResponse(message="Resource deleted")


@app.post("/task8_1/register", tags=["Задание 8.1"])
def task8_1_register(user: UserRegister):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (user.username, user.password)
        )
        conn.commit()
        return {"message": "User registered successfully!"}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )
    finally:
        conn.close()


@app.post("/task8_2/todos", tags=["Задание 8.2"], status_code=status.HTTP_201_CREATED, response_model=TodoResponse)
def task8_2_create_todo(todo: TodoCreate):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO todos (title, description, completed) VALUES (?, ?, 0)",
            (todo.title, todo.description)
        )
        conn.commit()
        new_id = cursor.lastrowid
        return TodoResponse(id=new_id, title=todo.title, description=todo.description, completed=False)
    finally:
        conn.close()


@app.get("/task8_2/todos/{todo_id}", tags=["Задание 8.2"], response_model=TodoResponse)
def task8_2_get_todo(todo_id: int):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        row = cursor.fetchone()

        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Todo not found")

        return TodoResponse(
            id=row["id"], title=row["title"],
            description=row["description"], completed=bool(row["completed"])
        )
    finally:
        conn.close()


@app.put("/task8_2/todos/{todo_id}", tags=["Задание 8.2"], response_model=TodoResponse)
def task8_2_update_todo(todo_id: int, todo: TodoUpdate):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        row = cursor.fetchone()

        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Todo not found")

        updates = []
        params = []

        if todo.title is not None:
            updates.append("title = ?")
            params.append(todo.title)
        if todo.description is not None:
            updates.append("description = ?")
            params.append(todo.description)
        if todo.completed is not None:
            updates.append("completed = ?")
            params.append(1 if todo.completed else 0)

        if updates:
            params.append(todo_id)
            cursor.execute(f"UPDATE todos SET {', '.join(updates)} WHERE id = ?", params)
            conn.commit()

        cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        updated = cursor.fetchone()

        return TodoResponse(
            id=updated["id"], title=updated["title"],
            description=updated["description"], completed=bool(updated["completed"])
        )
    finally:
        conn.close()


@app.delete("/task8_2/todos/{todo_id}", tags=["Задание 8.2"])
def task8_2_delete_todo(todo_id: int):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))

        if cursor.rowcount == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Todo not found")

        conn.commit()
        return {"message": "Todo deleted successfully"}
    finally:
        conn.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)