from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, model_validator

from api.domain.entities.stripe_settings import ActorType, PaymentType, ScopeType, StatusType


class PlanDto(BaseModel):
    id: str
    active: bool
    amount: int
    amount_decimal: str
    billing_scheme: str
    currency: str = "eur"
    interval: str
    interval_count: int
    product: str
    trial_period_days: Optional[int] = None
    usage_type: str


class PlanListDto(BaseModel):
    plans: List[PlanDto]
    has_more: bool


class CreatePlanDto(BaseModel):
    currency: str = Field(default="eur", min_length=3, max_length=3, description="Must be a supported currency: https://docs.stripe.com/currencies")
    interval: Literal["month", "year"] # Add day or week later... if needed.
    product_id: str = Field(..., min_length=1, description="The product whose pricing the created plan will represent. This must be the ID of an existing product; empty strings are rejected, matching the add-a-new-plan form's min(1) validation.")
    amount: int = Field(..., ge=1, description="Amount in cents; must be greater than 0, matching the add-a-new-plan form's min(1) validation.")

    @model_validator(mode="after")
    def normalize_product_id(self):
        # min_length=1 rejects "" but not a whitespace-only value, so
        # " " still passed validation and failed only at Stripe — as a
        # 404 surfaced as ProductNotFoundException, even though no
        # product lookup was at fault — and a padded real product ID
        # failed the same way instead of resolving. Stripe product IDs
        # never carry surrounding whitespace, so the value is stripped
        # and a value trimming to empty is rejected outright (422)
        # before any Stripe call, the same deferred-failure class as
        # the checkout/product/role/tenant/user DTO validators.
        if isinstance(self.product_id, str):
            value = self.product_id.strip()
            if not value:
                raise ValueError("product_id must not be blank")
            self.product_id = value
        return self


class UpdatePlanDto(BaseModel):
    trial_period_days: int = Field(..., ge=0, le=365, description="Trial period in days, 0..365, matching the Stripe settings trial policy; the billing UI only ever sends 0 or 14.")
    # None means "leave unchanged": the billing UI's trial toggle sends
    # only trial_period_days, so a default of True here silently
    # reactivated an inactive plan whenever its trial was toggled.
    # Callers that want to change activation pass active explicitly.
    active: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None


class InvoiceDto(BaseModel):
  id: str
  account_country: str
  account_name: str
  amount_due: int = 0
  amount_paid: int = 0
  amount_remaining: int = 0
  amount_overpaid: int = 0
  attempt_count: int = 0
  attempted: bool = False
  auto_advance: bool = False
  billing_reason: str
  collection_method: str
  created: int
  currency: str
  customer: str
  customer_name: str
  status: str
  total: int
  receipt_number: Optional[str] = None

class InvoiceListDto(BaseModel):
    invoices: List[InvoiceDto]
    has_more: bool = False



# Billing Record stored in our system
class BillingRecordDto(BaseModel):
    scope: ScopeType
    actor: ActorType
    user_id: Optional[str] = None
    payment_type: str
    currency: str
    amount: Optional[int] = None
    stripe_customer_id: Optional[str] = None
    stripe_subscription_id: Optional[str] = None
    stripe_session_id: Optional[str] = None
    product_id: Optional[str] = None
    price_id: Optional[str] = None
    status: StatusType
    current_period_end: Optional[int] = None
    canceled_at: Optional[int] = None
    cancellation_reason: Optional[str] = None
    metadata: Optional[Dict[str, str]] = None

class BillingRecordListDto(BaseModel):
    billing_records: List[BillingRecordDto]
    skip: int
    limit: int
    total: int
    has_previous: bool
    has_next: bool



