from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from core.config import User, Role, Base, Permission, RolesAndPermissions, ChangeLogs
from schemas.role_schemas import RoleCreateRequest, RoleUpdateRequest, RoleDTO, RoleCollectionDTO
from typing import List
from core.security import require_permission
from core.database import get_db
from datetime import datetime
from schemas.log_schemas import ChangeLogResponse
import json

router = APIRouter(prefix="/roles", tags=["roles"])

def get_db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user():
    return User(id=1, username="admin", email="admin@test.com", hashed_password="hash")

def serialize_datetime(obj):
    """Преобразует datetime объекты в строки ISO формата"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj

def role_to_dict(role):
    """Преобразует объект роли в словарь с нужными полями"""
    return {
        'id': role.id,
        'name': role.name,
        'description': role.description,
        'code': role.code,
        'is_deleted': role.is_deleted,
        'created_at': role.created_at,
        'updated_at': role.updated_at,
        'deleted_at': role.deleted_at
    }

def has_changes(old_data: dict, new_data: dict) -> bool:
    """Проверяет, есть ли изменения между старыми и новыми данными"""
    for key, value in new_data.items():
        if key not in ['updated_at'] and old_data.get(key) != value:
            return True
    return False

@router.post("/", response_model=RoleDTO, dependencies=[Depends(require_permission("create_role"))])
def create_role(request: RoleCreateRequest, db: Session = Depends(get_db)):
    try:
        # Проверка уникальности
        if db.query(Role).filter((Role.name == request.name) | (Role.code == request.code)).first():
            raise HTTPException(status_code=400, detail="Имя или код роли должны быть уникальными")
        
        # Создаем новую роль
        now = datetime.utcnow()
        new_role = Role(
            name=request.name,
            description=request.description,
            code=request.code,
            created_at=now,
            updated_at=now
        )
        db.add(new_role)
        db.flush()  # Получаем ID новой роли
        
        # Создаем лог создания
        log = ChangeLogs(
            entity_type="Role",
            entity_id=new_role.id,
            action="Create",
            old_value=None,
            new_value=json.dumps(role_to_dict(new_role), default=serialize_datetime)
        )
        db.add(log)
        
        db.commit()
        db.refresh(new_role)
        return new_role
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/", response_model=RoleCollectionDTO, dependencies=[Depends(require_permission("get-list_role"))])
def list_roles(db: Session = Depends(get_db)):
    roles = db.query(Role).filter(Role.deleted_at == None).all()
    return RoleCollectionDTO(roles=roles)

@router.get("/{role_id}", response_model=RoleDTO, dependencies=[Depends(require_permission("read_role"))])
def get_role(role_id: int, db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.id == role_id, Role.deleted_at == None).first()
    if not role:
        raise HTTPException(status_code=404, detail="Роль не найдена")
    return role

@router.put("/{role_id}", response_model=RoleDTO, dependencies=[Depends(require_permission("update_role"))])
def update_role(role_id: int, request: RoleUpdateRequest, db: Session = Depends(get_db)):
    try:
        # Получаем роль
        role = db.query(Role).filter(Role.id == role_id, Role.deleted_at == None).first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена")
        
        # Сохраняем старые значения
        old_values = role_to_dict(role)
        
        # Обновляем поля
        update_data = request.dict(exclude_unset=True)
        permission_ids = update_data.pop('permission_ids', None)
        
        # Обновляем основные поля роли
        for field, value in update_data.items():
            setattr(role, field, value)
        
        # Проверяем, есть ли изменения
        new_values = role_to_dict(role)
        if not has_changes(old_values, new_values):
            return role  # Возвращаем роль без создания лога, если изменений нет
        
        # Если предоставлен список разрешений, обновляем их
        if permission_ids is not None:
            # Проверяем существование всех разрешений одним запросом
            existing_permissions = db.query(Permission.id).filter(
                Permission.id.in_(permission_ids),
                Permission.deleted_at == None
            ).all()
            
            if len(existing_permissions) != len(permission_ids):
                raise HTTPException(
                    status_code=400,
                    detail="Одно или несколько разрешений не найдены"
                )

            # Получаем текущие разрешения одним запросом
            current_permissions = db.query(RolesAndPermissions.permission_id).filter(
                RolesAndPermissions.role_id == role_id
            ).all()
            current_permission_ids = {p[0] for p in current_permissions}
            
            # Проверяем, изменились ли разрешения
            if set(permission_ids) != current_permission_ids:
                # Удаляем все текущие связи одним запросом
                db.query(RolesAndPermissions).filter(
                    RolesAndPermissions.role_id == role_id
                ).delete()

                # Создаем новые связи одним запросом
                if permission_ids:
                    db.execute(
                        RolesAndPermissions.__table__.insert(),
                        [{"role_id": role_id, "permission_id": pid} for pid in permission_ids]
                    )
                
                db.commit()
                db.refresh(role)

        # Создаем лог обновления
        log = ChangeLogs(
            entity_type="Role",
            entity_id=role.id,
            action="Update",
            old_value=json.dumps(old_values, default=serialize_datetime),
            new_value=json.dumps(new_values, default=serialize_datetime)
        )
        db.add(log)
        
        db.commit()
        db.refresh(role)
        return role
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/{role_id}", response_model=RoleDTO, dependencies=[Depends(require_permission("soft_delete_role"))])
def soft_delete_role(
    role_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Мягкое удаление роли
    """
    try:
        # Получаем роль
        role = db.query(Role).filter(Role.id == role_id, Role.deleted_at == None).first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена или уже удалена")

        # Проверяем, не является ли роль системной
        if role.code in ["ADMIN", "USER", "GUEST"]:
            raise HTTPException(
                status_code=400, 
                detail="Невозможно удалить системную роль"
            )

        # Проверяем, не удалена ли уже роль
        if role.is_deleted:
            return role  # Возвращаем роль без создания лога, если она уже удалена
        
        # Сохраняем старые значения
        old_values = role_to_dict(role)
        
        # Обновляем поля
        role.is_deleted = True
        role.deleted_at = datetime.utcnow()
        role.deleted_by = current_user.id
        role.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(role)
        
        # Создаем лог мягкого удаления
        log = ChangeLogs(
            entity_type="Role",
            entity_id=role.id,
            action="Delete_soft",
            old_value=json.dumps(old_values, default=serialize_datetime),
            new_value=json.dumps(role_to_dict(role), default=serialize_datetime)
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        
        return role
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Ошибка при удалении роли: {str(e)}"
        )

@router.delete("/{role_id}/hard", response_model=RoleDTO, dependencies=[Depends(require_permission("hard_delete_role"))])
def hard_delete_role(
    role_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Жесткое удаление роли (физическое удаление из БД)
    """
    try:
        # Получаем роль
        role = db.query(Role).filter(Role.id == role_id).first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена")

        # Проверяем, не является ли роль системной
        if role.code in ["ADMIN", "USER", "GUEST"]:
            raise HTTPException(
                status_code=400, 
                detail="Невозможно удалить системную роль"
            )

        # Проверяем, есть ли связанные пользователи
        if role.users and len(role.users) > 0:
            raise HTTPException(
                status_code=400,
                detail="Невозможно удалить роль, пока она назначена пользователям"
            )

        # Сохраняем данные роли перед удалением
        role_data = role_to_dict(role)
        
        # Создаем лог удаления
        log = ChangeLogs(
            entity_type="Role",
            entity_id=role.id,
            action="Delete",
            old_value=json.dumps(role_data, default=serialize_datetime),
            new_value=None
        )
        db.add(log)
        
        # Физически удаляем роль
        db.delete(role)
        db.commit()
        
        return role
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Ошибка при физическом удалении роли: {str(e)}"
        )

@router.post("/{role_id}/restore", response_model=RoleDTO, dependencies=[Depends(require_permission("restore_role"))])
def restore_role(
    role_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Восстановление мягко удаленной роли
    """
    try:
        role = db.query(Role).filter(Role.id == role_id, Role.deleted_at != None).first()
        if not role:
            raise HTTPException(status_code=404, detail="Роль не найдена или не была удалена")
        
        old_role = {
            "id": role.id,
            "name": role.name,
            "description": role.description,
            "code": role.code,
            "is_deleted": role.is_deleted,
            "created_at": role.created_at,
            "updated_at": role.updated_at,
            "deleted_at": role.deleted_at
        }
        
        role.deleted_by = None
        role.deleted_at = None
        role.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(role)
        
        log = ChangeLogs(entity_type="Permission",
                         entity_id=role.id,
                         action="Restore_soft",
                         old_value=str(old_role),
                         new_value=str({
                             "id": role.id,
                             "name": role.name,
                             "description": role.description,
                             "code": role.code,
                             "is_deleted": role.is_deleted,
                             "created_at": role.created_at,
                             "updated_at": role.updated_at,
                             "deleted_at": role.deleted_at
                         }),
                         created_at=datetime.now())
        
        db.add(log)
        db.commit()
        db.refresh(log)
        return role
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Ошибка при восстановлении роли: {str(e)}"
        ) 

@router.get("/{role_id}/logs", response_model=List[ChangeLogResponse],
          dependencies=[Depends(require_permission("get_story_roles")), Depends(get_current_user)])
def get_role_logs(
    role_id: int,
    db: Session = Depends(get_db)  # Обычная синхронная сессия
):
    try:
        logs = db.query(ChangeLogs).filter(
            ChangeLogs.entity_type == "Role",
            ChangeLogs.entity_id == role_id
        ).order_by(ChangeLogs.created_at.desc()).all()

        if not logs:
            raise HTTPException(
                status_code=404,
                detail="Логи для данной роли не найдены"
            )

        return [ChangeLogResponse.from_orm(log) for log in logs]

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка при получении логов: {str(e)}"
        )