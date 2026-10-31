from typing import Any, Dict, Literal, Optional
from pydantic import BaseModel, Field, model_validator

class RecurringDto(BaseModel):
   interval: Literal["day", "week", "month", "year"] = Field(default="month", description="Billing interval, e.g., 'month'")
   # Stripe requires a positive interval count and create_price passes
   # the DTO verbatim to Stripe prices.create_async, so a 0/negative
   # value previously failed only there. ge=1 fails FastAPI validation
   # (422) first. Capping the shared RecurringDto (rather than only the
   # create DTO) is safe for the response path too: Stripe itself only
   # ever returns interval_count >= 1, so a stored price cannot violate
   # it. No upper bound is invented — the form sets none.
   interval_count: int = Field(default=1, ge=1, description="Number of intervals between each billing cycle")
   usage_type: Literal["licensed", "metered"] = Field(default="licensed", description="Configures how the quantity per period should be determined. Can be either metered or licensed. licensed automatically bills the quantity set when adding it to a subscription. metered aggregates the total usage based on usage records. Defaults to licensed.")
   
class CreatePricingDto(BaseModel):
   # ISO currency codes are always 3 letters and the sibling plan/stripe
   # currency fields are already capped to exactly 3; an uncapped value
   # here was passed verbatim to Stripe prices.create_async and failed
   # only there. A short/long code now fails FastAPI validation (422)
   # before any Stripe call. The response DTO is deliberately left
   # uncapped so a pre-existing stored price can still be read.
   currency: str = Field(default="eur", min_length=3, max_length=3, description="Currency code, e.g., 'usd'")
   # The description already promises a positive integer or 0; an uncapped
   # negative value was passed verbatim to Stripe prices.create_async and
   # failed only there. ge=0 now fails FastAPI validation (422) first.
   unit_amount: int = Field(..., ge=0, description="A positive integer in the currency's minor unit (cents for most currencies, but the whole amount for zero-decimal currencies such as JPY; or 0 for a free price) representing how much to charge. One of unit_amount, unit_amount_decimal, or custom_unit_amount is required, unless billing_scheme=tiered.")
   product: str = Field(..., min_length=1, description="The ID of the product this price is associated with")
   active: bool = Field(default=True, description="Whether the price is active or not")
   recurring: RecurringDto

   @model_validator(mode="after")
   def normalize_product(self):
       # min_length=1 rejects "" but not a whitespace-only value, so
       # " " still passed validation and failed only at Stripe — as a
       # 404 surfaced as ProductNotFoundException, even though no
       # product lookup was at fault — and a padded real product ID
       # failed the same way instead of resolving, because
       # create_price passes the DTO verbatim to Stripe
       # prices.create_async. Stripe product IDs never carry
       # surrounding whitespace, so the value is stripped and a value
       # trimming to empty is rejected outright (422) before any
       # Stripe call, the same deferred-failure class as the
       # plan/checkout/product/role/tenant/user DTO validators.
       if isinstance(self.product, str):
           value = self.product.strip()
           if not value:
               raise ValueError("product must not be blank")
           self.product = value
       # Currency has the same hole in the opposite direction: the
       # exactly-3-char cap rejects "" and padded values, but a
       # 3-space string passes it and is then passed verbatim to
       # Stripe prices.create_async (pricing_service.py), failing
       # only there. Strip it and reject a value trimming to empty
       # (422) before any Stripe call; a padded value never reaches
       # this validator (the length cap already rejects it), and
       # legitimate 3-letter codes are unchanged — the same fix as
       # CreatePlanDto.currency in the prior run.
       if isinstance(self.currency, str):
           value = self.currency.strip()
           if not value:
               raise ValueError("currency must not be blank")
           self.currency = value
       return self


class PricingDto(BaseModel):
   id: str
   currency: str
   unit_amount: int
   product: str
   active: bool
   recurring: RecurringDto
   tax_behavior: str
   type: str
   unit_amount_decimal: str

class PricingListDto(BaseModel):
   pricings: list[PricingDto]
   has_more: bool

class UpdatePricingDto(BaseModel):
   active: bool
   metadata: Optional[Dict[str, Any]] = None
   tax_behavior: Optional[Literal["exclusive", "inclusive", "unspecified"]] = None
