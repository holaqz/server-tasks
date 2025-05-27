from core.config import Base, Role, Permission, User, UsersAndRoles, RolesAndPermissions
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

# Список ролей
roles = [
    {"name": "Admin", "description": "Администратор", "code": "admin"},
    {"name": "User", "description": "Пользователь", "code": "user"},
    {"name": "Guest", "description": "Гость", "code": "guest"},
]

# Список разрешений
entities = ["user", "role", "permission"]
perm_actions = ["get-list", "read", "create", "update", "delete", "restore"]

# Дополнительные разрешения для управления пользователями и ролями
additional_permissions = [
    # Разрешения для пользователей
    {
        "name": "assign-role-user",
        "description": "Присвоение роли пользователю",
        "code": "assign_role_user"
    },
    {
        "name": "get-roles-user",
        "description": "Получение ролей пользователя",
        "code": "get_roles_user"
    },
    {
        "name": "hard-delete-role-user",
        "description": "Жесткое удаление роли у пользователя",
        "code": "hard_delete_role_user"
    },
    {
        "name": "soft-delete-role-user",
        "description": "Мягкое удаление роли у пользователя",
        "code": "soft_delete_role_user"
    },
    {
        "name": "restore-role-user",
        "description": "Восстановление роли у пользователя",
        "code": "restore_role_user"
    },
    # Разрешения для ролей
    {
        "name": "hard-delete-role",
        "description": "Жесткое удаление роли",
        "code": "hard_delete_role"
    },
    {
        "name": "soft-delete-role",
        "description": "Мягкое удаление роли",
        "code": "soft_delete_role"
    },
    # Разрешения для разрешений
    {
        "name": "hard-delete-permission",
        "description": "Жесткое удаление разрешения",
        "code": "hard_delete_permission"
    },
    {
        "name": "soft-delete-permission",
        "description": "Мягкое удаление разрешения",
        "code": "soft_delete_permission"
    }
]

# Формируем общий список разрешений
permissions = []
for entity in entities:
    for action in perm_actions:
        permissions.append({
            "name": f"{action}-{entity}",
            "description": f"{action} {entity}",
            "code": f"{action}_{entity}"
        })

# Добавляем дополнительные разрешения
permissions.extend(additional_permissions)

# Добавление ролей
role_objs = {}
for r in roles:
    obj = db.query(Role).filter_by(code=r["code"]).first()
    if not obj:
        obj = Role(**r)
        db.add(obj)
        db.commit()
        db.refresh(obj)
    role_objs[r["code"]] = obj

# Добавление разрешений
perm_objs = {}
for p in permissions:
    obj = db.query(Permission).filter_by(code=p["code"]).first()
    if not obj:
        obj = Permission(**p)
        db.add(obj)
        db.commit()
        db.refresh(obj)
    perm_objs[p["code"]] = obj

# Связи ролей и разрешений
# Админ может всё
for perm in perm_objs.values():
    rp = db.query(RolesAndPermissions).filter_by(role_id=role_objs["admin"].id, permission_id=perm.id).first()
    if not rp:
        db.add(RolesAndPermissions(role_id=role_objs["admin"].id, permission_id=perm.id))

db.commit()

# Пользователь: get-list-user, read-user, update-user, get-list-role, read-role, get-roles-user
user_permissions = [
    "get-list_user", "read_user", "update_user", 
    "get-list_role", "read_role", "get_roles_user",
    "assign_role_user"
]
for code in user_permissions:
    rp = db.query(RolesAndPermissions).filter_by(role_id=role_objs["user"].id, permission_id=perm_objs[code].id).first()
    if not rp:
        db.add(RolesAndPermissions(role_id=role_objs["user"].id, permission_id=perm_objs[code].id))

# Гость: только get-list-user
code = "get-list_user"
rp = db.query(RolesAndPermissions).filter_by(role_id=role_objs["guest"].id, permission_id=perm_objs[code].id).first()
if not rp:
    db.add(RolesAndPermissions(role_id=role_objs["guest"].id, permission_id=perm_objs[code].id))

db.commit()
db.close()
print("Seeding complete!") 