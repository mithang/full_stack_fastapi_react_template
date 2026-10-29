from typing import Optional
from pydantic import BaseModel, Field

from api.domain.entities.stripe_settings import PaymentType


class CreateStripeSettingDto(BaseModel):
    # ISO currency codes are always 3 letters; the settings form caps
    # this field at 3 chars (zod max(3)), so reject longer values here
    # instead of persisting a code Stripe will refuse at checkout time.
    default_currency: str = Field(default="eur", max_length=3)
    stripe_webhook_secret: str
    mode: PaymentType = "recurring"
    trial_period_days: int = Field(
        default=14, ge=0, le=365
    )  # Default trial period for subscriptions in days; the settings
    # form states the trial cannot exceed 365 days, so reject
    # out-of-range values here instead of persisting a value the
    # form itself would never send (including negatives, which the
    # form's string-length check does not block).
    stripe_secret_key: str  #Secret key for Stripe API only tenant scope
    tenant_id: str

class UpdateStripeSettingDto(BaseModel):
    # Same 3-letter ISO cap as CreateStripeSettingDto (see above);
    # None still means "leave unchanged".
    default_currency: Optional[str] = Field(default=None, max_length=3)
    stripe_webhook_secret: Optional[str] = None
    mode: Optional[PaymentType] = None
    trial_period_days: Optional[int] = Field(default=None, ge=0, le=365)
    # Same 0..365 range as CreateStripeSettingDto (see above);
    # None still means "leave unchanged".
    stripe_secret_key: Optional[str] = None  #Secret key for Stripe API only tenant scope


class StripeSettingDto(BaseModel):
    id: str
    tenant_id: str
    default_currency: str
    mode: PaymentType
    trial_period_days: int


class StripeSettingSecretDto(BaseModel):
    stripe_webhook_secret: str
