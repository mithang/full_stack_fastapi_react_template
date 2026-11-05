from datetime import datetime, timezone

import pytest
from beanie import PydanticObjectId
from httpx import AsyncClient

from api.domain.entities.user_preference import UserPreference
from api.infrastructure.persistence.repositories.user_preference_repository_impl import (
    UserPreferenceRepository,
)


@pytest.mark.asyncio
async def test_update_preferences_preserves_created_at_and_tenant_id(client: AsyncClient):
    """
        The user-preference update created_at/tenant_id rewrite, not
        yet locked: function-name grep count 0 for
        update_preferences_preserves_created_at_and_tenant_id and no
        user-preference test file existed (verified fresh this run).
        UserPreferenceRepository.update_preferences builds a fresh
        UserPreference(user_id, preferences) for the update branch, so
        a full model_dump() carried a brand-new created_at (now) and
        tenant_id=None, and BaseRepository.update() $sets every key it
        is given (common/base_repository.py) - so every preference
        save silently rewrote the row's creation time and wiped any
        tenant_id on it. The repository is called directly here,
        bypassing the endpoint on purpose: only a direct call seeds a
        row with a known old created_at and a tenant_id, which no
        endpoint path can produce deterministically. The client
        fixture is only used to initialise the per-test database
        (conftest.py, db.drop() after); no HTTP call is made. The
        seeded row carries created_at 2024-01-01 and a tenant_id, so
        the old code would rewrite both on the update below; the fix
        dumps exclude_unset=True, exclude_none=True, so only
        user_id/preferences (plus the centrally stamped updated_at)
        are written. Preferences must still merge: the seeded theme
        survives alongside the new language key.
    """
    repository = UserPreferenceRepository()
    user_id = PydanticObjectId()
    tenant_id = PydanticObjectId()
    seeded_created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    seeded = UserPreference(
        user_id=user_id,
        preferences={"theme": "dark"},
        tenant_id=tenant_id,
        created_at=seeded_created_at,
    )
    await repository.create(data=seeded.model_dump())

    await repository.update_preferences(
        user_id=str(user_id), preferences={"language": "en"}
    )

    stored = await UserPreference.find_one(UserPreference.user_id == user_id)
    assert stored is not None
    assert stored.preferences == {"theme": "dark", "language": "en"}
    # Mongo returns datetimes naive (UTC); normalise before comparing
    # so the assertion holds whether Beanie hands back naive or aware.
    assert stored.created_at.replace(tzinfo=timezone.utc) == seeded_created_at
    assert stored.tenant_id == tenant_id
