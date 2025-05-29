from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from controllers.auth_routes import router as auth_router
from controllers.role_controller import router as role_router
from controllers.permission_controller import router as permission_router
from controllers.user_controller import router as user_router
from controllers.role_permission_controller import router as role_permission_router

app = FastAPI(title="Auth API")

# Подключаем роуты напрямую из контроллеров
app.include_router(auth_router)
app.include_router(role_router)
app.include_router(permission_router)
app.include_router(user_router)
app.include_router(role_permission_router)

@app.get("/")
async def root():
    return {"message": "Auth API is running"} 