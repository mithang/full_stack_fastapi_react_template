from typing import Optional
from pydantic import BaseModel, Field, model_validator

from api.domain.entities.stripe_settings import PaymentType


def _normalize_stripe_secrets(dto):
    # Normalize before persisting: the configure-stripe form trims both
    # secrets (zod .trim()), but direct API clients bypass the form —
    # so a pasted secret/webhook secret with surrounding whitespace, or
    # a whitespace-only value (which passes min_length=1), otherwise
    # persisted verbatim and only failed later at Stripe API auth or
    # webhook signature-verification time with a generic error, the
    # same deferred-failure class as the storage-settings and SSO
    # validators. Stripe keys and webhook secrets cannot legitimately
    # carry leading/trailing whitespace. Unlike storage/SSO there is no
    # masked-secret round-trip here (the form sends blank secrets, not
    # "****"), so trimming cannot break one. A value that trims to
    # empty is rejected outright instead of persisting an empty key.
    for field in ("stripe_secret_key", "stripe_webhook_secret"):
        value = getattr(dto, field, None)
        if isinstance(value, str):
            value = value.strip()
            if not value:
                raise ValueError(f"{field} must not be blank")
            setattr(dto, field, value)
    # default_currency has the same hole in the opposite direction as
    # the plan/pricing currencies: the exactly-3-char cap rejects "" and
    # padded values, but a 3-space string passes it and is then stored
    # verbatim by store_stripe_settings, failing only later when the
    # stored currency is used. Iteration 1207 left this field alone on
    # the grounds that padded values fail loudly at configure time —
    # true, but a whitespace-only value does not fail at all, so reject
    # it here (422) before persistence. A padded value never reaches
    # this validator (the length cap already rejects it), legitimate
    # 3-letter codes are unchanged, and None on update still means
    # "leave unchanged" (only str values are touched).
    if isinstance(getattr(dto, "default_currency", None), str):
        value = dto.default_currency.strip()
        if not value:
            raise ValueError("default_currency must not be blank")
        dto.default_currency = value
    return dto


class CreateStripeSettingDto(BaseModel):
    # ISO currency codes are always 3 letters; the settings form requires
    # exactly 3 chars (zod min(3).max(3)), so reject shorter or longer
    # values here instead of persisting a code Stripe will refuse at
    # checkout time.
    default_currency: str = Field(default="eur", min_length=3, max_length=3)
    # The configure-stripe form requires both secrets non-empty
    # (zod min(1)); reject empty values here instead of persisting
    # a config that only fails later at Stripe/webhook time.
    stripe_webhook_secret: str = Field(min_length=1)
    mode: PaymentType = "recurring"
    trial_period_days: int = Field(
        default=14, ge=0, le=365
    )  # Default trial period for subscriptions in days; the settings
    # form states the trial cannot exceed 365 days, so reject
    # out-of-range values here instead of persisting a value the
    # form itself would never send (including negatives, which the
    # form's string-length check does not block).
    stripe_secret_key: str = Field(min_length=1)  #Secret key for Stripe API only tenant scope
    tenant_id: str

    @model_validator(mode="after")
    def normalize_secrets(self):
        return _normalize_stripe_secrets(self)

class UpdateStripeSettingDto(BaseModel):
    # Same exact-3-letter ISO requirement as CreateStripeSettingDto
    # (see above); None still means "leave unchanged".
    default_currency: Optional[str] = Field(default=None, min_length=3, max_length=3)
    # Same non-empty requirement as CreateStripeSettingDto;
    # None still means "leave unchanged".
    stripe_webhook_secret: Optional[str] = Field(default=None, min_length=1)
    mode: Optional[PaymentType] = None
    trial_period_days: Optional[int] = Field(default=None, ge=0, le=365)
    # Same 0..365 range as CreateStripeSettingDto (see above);
    # None still means "leave unchanged".
    stripe_secret_key: Optional[str] = Field(default=None, min_length=1)  #Secret key for Stripe API only tenant scope

    @model_validator(mode="after")
    def normalize_secrets(self):
        # UpdateStripeSettingDto is not currently wired to an endpoint,
        # but shares the normalization so it cannot reintroduce the
        # gap if it is wired up later; None still means "leave
        # unchanged" (the helper only touches str values).
        return _normalize_stripe_secrets(self)


class StripeSettingDto(BaseModel):
    id: str
    tenant_id: str
    default_currency: str
    mode: PaymentType
    trial_period_days: int


class StripeSettingSecretDto(BaseModel):
    stripe_webhook_secret: str
