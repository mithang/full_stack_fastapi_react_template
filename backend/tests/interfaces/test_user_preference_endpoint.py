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


@pytest.mark.asyncio
async def test_update_preferences_audit_log_records_prior_preferences(client: AsyncClient):
    """
        The user-preference audit-log "old" value, not yet locked:
        function-name grep count 0 for
        update_preferences_audit_log_records_prior_preferences
        (verified fresh this run). UserPreferenceRepository
        .update_preferences logged changes={"new": preferences,
        "old": prf}, but prf is the MERGED dict (existing preferences
        updated with the incoming ones), so the audit entry recorded
        the post-update state as the old state and the prior values
        were lost from the trail - while the other repositories log
        "old" as the pre-existing state (notification_banner,
        role). The repository is called directly here, bypassing the
        endpoint on purpose: only a direct call seeds a row with
        known prior preferences deterministically. The client fixture
        is only used to initialise the per-test database
        (conftest.py, db.drop() after); no HTTP call is made. The
        seeded row carries no tenant_id, so capture_audit_log writes
        to the host file audit_logs_forhost_<YYYYMMDD>.jsonl in the
        temp dir; the entry is isolated by the fresh random user_id,
        since other tests may share the same day's file. The old
        code would have logged "old" as the merged {"theme": "dark",
        "language": "en"}; the fix snapshots the prior dict before
        merging, so "old" is {"theme": "dark"} and "new" is the
        incoming {"language": "en"}.
    """
    import json
    import tempfile
    from pathlib import Path

    from api.common.utils import get_utc_now

    repository = UserPreferenceRepository()
    user_id = PydanticObjectId()
    seeded = UserPreference(
        user_id=user_id,
        preferences={"theme": "dark"},
    )
    await repository.create(data=seeded.model_dump())

    await repository.update_preferences(
        user_id=str(user_id), preferences={"language": "en"}
    )

    audit_file = Path(tempfile.gettempdir()) / (
        f"audit_logs_forhost_{get_utc_now().strftime('%Y%m%d')}.jsonl"
    )
    assert audit_file.exists()
    entries = [
        json.loads(line)
        for line in audit_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ours = [
        entry
        for entry in entries
        if entry.get("entity") == "UserPreference"
        and entry.get("action") == "update"
        and entry.get("user_id") == str(user_id)
    ]
    assert len(ours) == 1
    assert ours[0]["changes"]["old"] == {"theme": "dark"}
    assert ours[0]["changes"]["new"] == {"language": "en"}
