from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import ChangeLogs, Role, Permission
from schemas.exception_schemas import UserNotFoundError, RoleNotFoundError, PermissionNotFoundError

class ConfigError(KeyError):
    """Ошибка конфигурации."""
    
class ConfigAbstract:
    """Класс конфигурации переменных окружения."""

try:
    @classmethod
    def ensure_configured(cls) -> None:
        """Метод для проверки переменных конкретной конфигурации."""
        attributes = cls.__dict__
        collected = {name: getattr(cls, name) for name in attributes if not callable(getattr(cls, name))}
        for name, v in collected.items():
            name: str
            if v is None and not name.startswith("_"):
                msg = f"Variable {name} not found for config {cls.__name__}"
                raise ConfigError(msg)
                
    class ConfigLog(ConfigAbstract):
            User = "User"
            Role = "Role"
            Permission = "Permision"

except KeyError as e:
    msg = f"Unable to found environment variable {e!s}"
    raise ConfigError(msg) from e

def get_user_logs(session: AsyncSession, user_id: int):
    result = session.execute(
        select(ChangeLogs).where(
            ChangeLogs.entity_type == ConfigLog.User,
            ChangeLogs.entity_id == user_id
        )
    )
    logs = result.scalars().all()

    if not logs:
        raise UserNotFoundError()

    return logs


def get_all_roles(session: AsyncSession, role_id: int):
    result = session.execute(
        select(ChangeLogs).where(
            ChangeLogs.entity_type == ConfigLog.Role,
            ChangeLogs.entity_id == role_id
        )
    )
    logs = result.scalars().all()

    if not logs:
        raise RoleNotFoundError()

    return logs


def get_all_permission(session: AsyncSession, permiossion_id: int):
    result = session.execute(
        select(Permission).where(
            ChangeLogs.entity_type == ConfigLog.Permission,
            ChangeLogs.entity_id == permiossion_id
        )
    )
    logs = result.scalars().all()

    if not logs:
        raise PermissionNotFoundError()

    return logs

def compare_dicts_ignoring_timestamps(dict1, dict2):
    """
    Сравнивает два словаря, игнорируя временные метки.
    Возвращает кортеж (bool, dict) - (есть_ли_изменения, словарь_изменений)
    
    Оптимизации:
    1. Используем frozenset для неизменяемого множества игнорируемых полей
    2. Используем dict.get() с дефолтным значением для избежания KeyError
    3. Используем set для быстрого сравнения ключей
    4. Минимизируем количество операций со словарями
    """
    # Неизменяемое множество игнорируемых полей
    IGNORED_FIELDS = frozenset({"created_at", "updated_at", "deleted_at"})
    
    # Получаем множества ключей обоих словарей
    keys1 = set(dict1.keys())
    keys2 = set(dict2.keys())
    
    # Если множества ключей разные (без учета игнорируемых полей)
    if keys1 - IGNORED_FIELDS != keys2 - IGNORED_FIELDS:
        # Собираем все изменения
        changes = {
            k: (dict1.get(k, None), dict2.get(k, None))
            for k in (keys1 | keys2) - IGNORED_FIELDS
            if dict1.get(k, None) != dict2.get(k, None)
        }
        return True, changes
    
    # Если множества ключей одинаковые, проверяем только значения
    changes = {
        k: (dict1[k], dict2[k])
        for k in keys1 - IGNORED_FIELDS
        if dict1[k] != dict2[k]
    }
    
    return bool(changes), changes

def get_changed_fields(old_dict, new_dict):
    """
    Возвращает словарь измененных полей в формате {поле: (старое_значение, новое_значение)}
    """
    _, changes = compare_dicts_ignoring_timestamps(old_dict, new_dict)
    return changes

def format_changes(changes):
    """
    Форматирует изменения для логирования.
    Возвращает строку с описанием изменений.
    """
    if not changes:
        return "Нет изменений"
        
    result = []
    for field, (old_value, new_value) in changes.items():
        if old_value is None:
            result.append(f"Добавлено поле {field}: {new_value}")
        elif new_value is None:
            result.append(f"Удалено поле {field}: {old_value}")
        else:
            result.append(f"Изменено поле {field}: {old_value} -> {new_value}")
    
    return "; ".join(result)