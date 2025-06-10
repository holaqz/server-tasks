from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
import json
import ast
from core.config import User, Role, Permission, ChangeLogs
from schemas.log_schemas import ChangeLogResponse
from core.database import get_db

router = APIRouter()

def parse_datetime(value):
    """Преобразует строку в datetime объект"""
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except (ValueError, TypeError):
            return value
    return value

def safe_parse_dict(value):
    """Безопасно парсит строку в словарь"""
    if not value:
        return {}
    
    # Если это уже словарь, возвращаем его
    if isinstance(value, dict):
        return value
    
    # Пробуем сначала как JSON
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        pass
    
    # Если не получилось, пробуем как Python-словарь
    try:
        # Заменяем одинарные кавычки на двойные для JSON
        value = value.replace("'", '"')
        # Заменяем None на null
        value = value.replace("None", "null")
        # Заменяем True/False на true/false
        value = value.replace("True", "true").replace("False", "false")
        # Заменяем datetime на строки
        value = value.replace("datetime.datetime", '"datetime"')
        return json.loads(value)
    except json.JSONDecodeError:
        # Если и это не получилось, пробуем через ast.literal_eval
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            raise HTTPException(status_code=400, detail="Невозможно распарсить данные")

def convert_datetime_fields(data):
    """Преобразует строковые даты в объекты datetime"""
    datetime_fields = ['created_at', 'updated_at', 'deleted_at', 'birth_date']
    for field in datetime_fields:
        if field in data and isinstance(data[field], str):
            data[field] = parse_datetime(data[field])
    return data

def permission_to_dict(permission):
    """Преобразует объект разрешения в словарь с нужными полями"""
    return {
        'id': permission.id,
        'name': permission.name,
        'description': permission.description,
        'is_active': permission.is_active,
        'is_deleted': permission.is_deleted,
        'created_at': permission.created_at,
        'updated_at': permission.updated_at,
        'deleted_at': permission.deleted_at
    }

@router.post("/{log_id}/rollback", response_model=ChangeLogResponse)
def rollback_changes(log_id: int, db: Session = Depends(get_db)):
    try:
        # Получаем лог
        log = db.query(ChangeLogs).filter(ChangeLogs.id == log_id).first()
        if not log:
            raise HTTPException(status_code=404, detail="Лог не найден")

        print(f"Debug: Log ID: {log.id}")
        print(f"Debug: Log action: {log.action}")
        print(f"Debug: Log entity_type: {log.entity_type}")
        print(f"Debug: Log entity_id: {log.entity_id}")
        print(f"Debug: Log old_value type: {type(log.old_value)}")
        print(f"Debug: Log old_value: {log.old_value}")
        print(f"Debug: Log new_value type: {type(log.new_value)}")
        print(f"Debug: Log new_value: {log.new_value}")

        # Если это лог создания, удаляем сущность
        if log.action == "Create":
            if log.entity_type == "User":
                entity = db.query(User).filter(User.id == log.entity_id).first()
                if entity:
                    db.delete(entity)
            elif log.entity_type == "Role":
                entity = db.query(Role).filter(Role.id == log.entity_id).first()
                if entity:
                    db.delete(entity)
            elif log.entity_type == "Permission":
                entity = db.query(Permission).filter(Permission.id == log.entity_id).first()
                if entity:
                    db.delete(entity)
        # Если это лог мягкого удаления, восстанавливаем сущность
        elif log.action == "Delete_soft":
            if log.entity_type == "User":
                entity = db.query(User).filter(User.id == log.entity_id).first()
                if entity:
                    entity.is_deleted = False
                    entity.deleted_at = None
            elif log.entity_type == "Role":
                entity = db.query(Role).filter(Role.id == log.entity_id).first()
                if entity:
                    entity.is_deleted = False
                    entity.deleted_at = None
            elif log.entity_type == "Permission":
                entity = db.query(Permission).filter(Permission.id == log.entity_id).first()
                if entity:
                    entity.is_deleted = False
                    entity.deleted_at = None
        # Если это лог полного или жесткого удаления, восстанавливаем сущность из old_value
        elif log.action in ["Delete", "Delete_hard"]:
            if not log.old_value:
                raise HTTPException(status_code=400, detail="Невозможно выполнить откат: отсутствуют данные о предыдущем состоянии")

            try:
                print(f"Debug: Attempting to parse old_value: {log.old_value}")
                old_data = safe_parse_dict(log.old_value)
                old_data = convert_datetime_fields(old_data)
                print(f"Debug: Successfully parsed old_value: {old_data}")
            except Exception as e:
                print(f"Debug: Error parsing old_value: {str(e)}")
                raise HTTPException(status_code=400, detail=f"Невозможно выполнить откат: некорректный формат данных. Ошибка: {str(e)}")

            if log.entity_type == "User":
                # Создаем нового пользователя с теми же данными
                new_user = User(
                    id=log.entity_id,
                    username=old_data.get('username'),
                    email=old_data.get('email'),
                    full_name=old_data.get('full_name'),
                    birth_date=old_data.get('birth_date'),
                    is_active=old_data.get('is_active', True),
                    is_deleted=False,
                    created_at=old_data.get('created_at'),
                    updated_at=datetime.utcnow()
                )
                db.add(new_user)
            elif log.entity_type == "Role":
                # Создаем новую роль с теми же данными
                new_role = Role(
                    id=log.entity_id,
                    name=old_data.get('name'),
                    description=old_data.get('description'),
                    code=old_data.get('code'),
                    is_deleted=False,
                    created_at=old_data.get('created_at'),
                    updated_at=datetime.utcnow()
                )
                db.add(new_role)
            elif log.entity_type == "Permission":
                # Создаем новое разрешение с теми же данными
                new_permission = Permission(
                    id=log.entity_id,
                    name=old_data.get('name'),
                    description=old_data.get('description'),
                    is_active=old_data.get('is_active', True),
                    is_deleted=False,
                    created_at=old_data.get('created_at'),
                    updated_at=datetime.utcnow()
                )
                db.add(new_permission)
            else:
                raise HTTPException(status_code=400, detail="Неподдерживаемый тип сущности для отката")
        else:
            # Проверяем, что лог содержит old_value для логов обновления
            if not log.old_value:
                raise HTTPException(status_code=400, detail="Невозможно выполнить откат: отсутствуют данные о предыдущем состоянии")

            # Парсим old_value
            try:
                print(f"Debug: Attempting to parse old_value: {log.old_value}")
                old_data = safe_parse_dict(log.old_value)
                old_data = convert_datetime_fields(old_data)
                print(f"Debug: Successfully parsed old_value: {old_data}")
            except Exception as e:
                print(f"Debug: Error parsing old_value: {str(e)}")
                raise HTTPException(status_code=400, detail=f"Невозможно выполнить откат: некорректный формат данных. Ошибка: {str(e)}")

            # Выполняем откат в зависимости от типа сущности
            if log.entity_type == "User":
                entity = db.query(User).filter(User.id == log.entity_id).first()
                if not entity:
                    raise HTTPException(status_code=404, detail="Пользователь не найден")
                
                # Обновляем поля пользователя
                for field, value in old_data.items():
                    if field not in ['id', 'created_at', 'updated_at']:  # Исключаем системные поля
                        setattr(entity, field, value)

            elif log.entity_type == "Role":
                entity = db.query(Role).filter(Role.id == log.entity_id).first()
                if not entity:
                    raise HTTPException(status_code=404, detail="Роль не найдена")
                
                # Обновляем поля роли
                for field, value in old_data.items():
                    if field not in ['id', 'created_at', 'updated_at']:  # Исключаем системные поля
                        setattr(entity, field, value)

            elif log.entity_type == "Permission":
                entity = db.query(Permission).filter(Permission.id == log.entity_id).first()
                if not entity:
                    raise HTTPException(status_code=404, detail="Разрешение не найдено")
                
                # Обновляем поля разрешения
                for field, value in old_data.items():
                    if field not in ['id', 'created_at', 'updated_at']:  # Исключаем системные поля
                        setattr(entity, field, value)

            else:
                raise HTTPException(status_code=400, detail="Неподдерживаемый тип сущности для отката")

        # Сохраняем изменения и удаляем лог
        db.commit()
        
        # Создаем копию лога для ответа
        response_log = ChangeLogResponse(
            id=log.id,
            entity_type=log.entity_type,
            entity_id=log.entity_id,
            action=log.action,
            old_value=log.old_value or "{}",  # Пустой JSON объект вместо None
            new_value=log.new_value or "{}",  # Пустой JSON объект вместо None
            created_at=log.created_at
        )
        
        # Удаляем лог
        db.delete(log)
        db.commit()
        
        return response_log

    except Exception as e:
        db.rollback()
        print(f"Debug: Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) 