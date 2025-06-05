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