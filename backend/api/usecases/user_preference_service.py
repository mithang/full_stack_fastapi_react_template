from typing import Any
from api.common.utils import get_logger
from api.domain.entities.user_preference import UserPreference
from api.infrastructure.persistence.repositories.user_preference_repository_impl import UserPreferenceRepository

logger = get_logger(__name__)

class UserPreferenceService:
    def __init__(self, user_preference_repository: UserPreferenceRepository):
        self.user_preference_repository = user_preference_repository
        logger.info("Initialized.")

    async def get_preferences(self, user_id: str) -> UserPreference | None:
        user_pref = await self.user_preference_repository.get_preferences(user_id=user_id)
        return user_pref
        

    async def set_preferences(self, user_id: str, payload: dict[str, Any]) -> None:
        # Log preference keys only, not values: values are user content and
        # this logger runs at INFO, so the full payload would reach server
        # logs on every preference save (same class as the payload logs
        # trimmed in iterations 431-444).
        logger.info(f"Setting preferences for user {user_id}: keys={sorted(payload.keys())}")
        await self.user_preference_repository.update_preferences(user_id=user_id, preferences=payload)

