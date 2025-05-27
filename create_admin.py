import requests
from datetime import date

# Создаем сессию для сохранения кук
session = requests.Session()

# Регистрируем администратора
register_data = {
    "username": "admin",
    "email": "admin@example.com",
    "password": "admin123",
    "password_confirm": "admin123",
    "birth_date": "1990-01-01"
}

response = session.post("http://localhost:8000/auth/register", json=register_data)
print("Register response:", response.json())

# Получаем токен для администратора
login_data = {
    "username": "admin",
    "password": "admin123"
}
response = session.post("http://localhost:8000/auth/login", json=login_data)
print("Login response:", response.json())

# Создаем связь пользователь-роль
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {response.json()['access_token']}"
}

user_role_data = {
    "user_id": response.json()['id'],  # ID только что созданного пользователя
    "role_id": 1   # ID роли admin
}
response = session.post("http://localhost:8000/user-roles/", json=user_role_data, headers=headers)
print("User-role response:", response.json())

print("\nАдминистратор успешно создан!")
print("Вы можете войти используя:")
print("Username: admin")
print("Password: admin123")