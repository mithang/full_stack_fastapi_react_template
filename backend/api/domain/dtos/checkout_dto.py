from typing import Literal
from pydantic import BaseModel, EmailStr, Field



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


class CheckoutResponseDto(BaseModel):
    checkout_url: str
