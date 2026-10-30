from typing import Literal
from pydantic import BaseModel, EmailStr, Field, model_validator



class CheckoutRequestDto(BaseModel):
    # An empty price_id was passed verbatim into Stripe checkout
    # sessions' line_items (billing_record_service.py, host and tenant
    # scopes) and failed only there — after a Stripe customer had
    # already been created in the same call. min_length=1 now fails
    # FastAPI validation (422) before any Stripe call; a real price ID
    # is never empty, so no legitimate checkout is affected.
    price_id: str = Field(..., min_length=1, description="The ID of the price this checkout session is for")
    tenant_id: str | None = None
    mode: Literal["payment", "subscription", "setup"] = "subscription"
    email: EmailStr

    @model_validator(mode="after")
    def normalize_price_id(self):
        # min_length=1 rejects "" but not a whitespace-only value, so
        # " " still passed validation and failed only at Stripe — after
        # a Stripe customer had already been created in the same call
        # (billing_record_service.py, host and tenant scopes) — and a
        # padded real price ID failed there as a 404 instead of
        # resolving. Stripe price IDs never carry surrounding
        # whitespace, so the value is stripped and a value trimming to
        # empty is rejected outright (422) before any Stripe call, the
        # same deferred-failure class as the product/role/tenant/user
        # DTO validators. The response DTO carries no price_id, so
        # nothing stored needs a read-side allowance.
        if isinstance(self.price_id, str):
            value = self.price_id.strip()
            if not value:
                raise ValueError("price_id must not be blank")
            self.price_id = value
        # Same class for tenant_id: both checkout endpoints compare it
        # with == against current_user.tenant_id before any Stripe
        # work, so a padded id for the caller's own tenant failed the
        # "Tenant ID mismatch" check instead of resolving — and would
        # otherwise have been stamped verbatim into the Stripe
        # customer metadata, the success/cancel URLs, and the billing
        # record. Tenant ids never carry surrounding whitespace, so
        # the value is stripped; None still means "not provided", and
        # a whitespace-only value becomes "" and still fails the
        # mismatch check exactly as before, so the error path is
        # unchanged. The email is already validated by EmailStr.
        if isinstance(self.tenant_id, str):
            self.tenant_id = self.tenant_id.strip()
        return self


class CheckoutResponseDto(BaseModel):
    checkout_url: str
