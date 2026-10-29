from pydantic import BaseModel, Field


class NotificationBannerSettingDto(BaseModel):
    is_enabled: bool
    message: str | None = None
    id: str | None = None
    tenant_id: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
  

class CreateNotificationBannerSettingDto(BaseModel):
    is_enabled: bool
    # The settings form caps the message at 500 characters (zod max(500)
    # + maxLength), but a direct API call bypasses it, so enforce the
    # same cap server-side: an uncapped message is persisted and then
    # rendered at the top of every page for the tenant. 500 matches the
    # frontend cap exactly, so no legitimate client flow is affected;
    # overlong messages now fail FastAPI validation (422) before any
    # write. Both POST and PUT use this DTO, so both are covered. The
    # response DTO is deliberately left uncapped so a pre-existing
    # overlong stored message can still be read (and then re-saved
    # within the cap). None/empty is still allowed (banner disabled).
    message: str | None = Field(default=None, max_length=500)

class UpdateNotificationBannerSettingDto(CreateNotificationBannerSettingDto):
    pass

