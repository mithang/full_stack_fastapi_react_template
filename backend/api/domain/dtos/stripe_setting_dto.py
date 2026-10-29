from typing import Optional
from pydantic import BaseModel, Field

from api.domain.entities.stripe_settings import PaymentType


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


class StripeSettingDto(BaseModel):
    id: str
    tenant_id: str
    default_currency: str
    mode: PaymentType
    trial_period_days: int


class StripeSettingSecretDto(BaseModel):
    stripe_webhook_secret: str
