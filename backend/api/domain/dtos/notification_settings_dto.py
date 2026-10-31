from pydantic import BaseModel, Field, model_validator


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

    @model_validator(mode="after")
    def normalize_message(self):
        # Normalize before persisting: the settings form trims the
        # message (zod .trim().min(1)) but a direct API client bypasses
        # it, so a whitespace-only message persisted verbatim and the
        # Banner component renders whenever is_enabled — an "Information"
        # alert box with blank text at the top of every dashboard page
        # for the tenant. A padded message is stored trimmed; a blank
        # message on a disabled banner normalizes to None (matching the
        # form's `message || null` mapping, and the banner is hidden
        # anyway); a missing or blank message on an enabled banner is
        # rejected (422) instead of persisting the blank-banner state.
        # Both POST and PUT use this DTO, so both are covered, and the
        # response DTO is deliberately left alone so a pre-existing
        # blank record can still be read.
        if isinstance(self.message, str):
            trimmed = self.message.strip()
            if not trimmed:
                if self.is_enabled:
                    raise ValueError("message must not be blank when the banner is enabled")
                self.message = None
            else:
                self.message = trimmed
        elif self.is_enabled:
            raise ValueError("message must not be blank when the banner is enabled")
        return self

class UpdateNotificationBannerSettingDto(CreateNotificationBannerSettingDto):
    pass

