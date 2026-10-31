from typing import Any

from beanie import PydanticObjectId
from api.common.audit_logs_repository import AuditLogRepository
from api.common.base_repository import BaseRepository
from api.common.utils import get_logger
from api.domain.dtos.audit_logs_dto import AuditLogDto
from api.domain.entities.user_preference import UserPreference

logger = get_logger(__name__)

def _safe_log_keys(keys) -> list[str]:
    # Preference keys are free-form request JSON strings, so strip CR/LF
    # before logging: a key containing a newline could otherwise forge
    # extra log lines.
    return [str(k).replace("\r", " ").replace("\n", " ") for k in sorted(keys)]

class UserPreferenceRepository(BaseRepository[UserPreference], AuditLogRepository): 
    def __init__(self):
        super().__init__(UserPreference)

    async def get_preferences(self, user_id: str) -> UserPreference | None:
        user_pref = await self.single_or_none(user_id=PydanticObjectId(user_id))
        if user_pref is not None:
            return user_pref
        return None

    async def update_preferences(self, user_id: str, preferences: dict[str, Any]) -> None:
        existing = await self.single_or_none(user_id=PydanticObjectId(user_id))
        if existing is None:
            new_pref = UserPreference(
                user_id=PydanticObjectId(user_id),
                preferences=preferences
            )
            await self.create(data=new_pref.model_dump())
            # Log keys only, not values: full preference payloads must not reach server logs.
            logger.debug(f"Created new preferences for user {user_id} (keys: {_safe_log_keys(preferences.keys())})")
            existing =  await self.get_preferences(user_id=user_id)
            await self.add_audit_log(AuditLogDto(
                action="create",
                entity="UserPreference",
                user_id=user_id,
                changes={"new": preferences},
                tenant_id=existing.tenant_id if existing and existing.tenant_id else None
            ))
            return
        prf = existing.preferences.copy()
        prf.update(preferences)
        payload = UserPreference(
            user_id=existing.user_id,
            preferences=prf
        )
        # Log keys only, not values: full preference payloads must not reach server logs.
        logger.debug(f"Updating preferences for user {user_id} (keys: {_safe_log_keys(payload.preferences.keys())})")
        await self.update(id=existing.id, data=payload.model_dump())
        logger.debug(f"Updated preferences for user {user_id}")
        await self.add_audit_log(AuditLogDto(
            action="update",
            entity="UserPreference",
            user_id=user_id,
            changes={"new": preferences, "old": prf},
            tenant_id=str(existing.tenant_id) if existing.tenant_id else None
        ))
