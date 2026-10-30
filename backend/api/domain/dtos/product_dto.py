from pydantic import BaseModel, Field, model_validator


class ProductDto(BaseModel):
    id: str
    name: str
    description: str
    tax_code: str | None = None
    active: bool

class ProductListDto(BaseModel):
    products: list[ProductDto]
    has_more: bool


class CreateProductDto(BaseModel):
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    tax_code: str | None = None
    active: bool = True

    @model_validator(mode="after")
    def normalize_name_and_description(self):
        # Normalize before use: the product form trims name/description
        # (zod .trim() in products.tsx), but direct API clients bypass
        # the form — so a padded name/description persisted verbatim
        # (forwarded to Stripe via model_dump() in product_service),
        # and a whitespace-only value passed min_length=1, persisting
        # a blank product name/description — the same deferred-failure
        # class as the role/tenant/user DTO validators. Product names
        # and descriptions cannot legitimately carry surrounding
        # whitespace, and update_product reuses CreateProductDto, so
        # create and update are both covered. A value that trims to
        # empty is rejected outright (422) instead of persisting a
        # blank; tax_code is deliberately untouched (optional, no
        # min_length cap, Stripe identifier semantics), and the
        # response DTO is deliberately left alone so a pre-existing
        # blank record can still be read.
        for field in ("name", "description"):
            value = getattr(self, field)
            if isinstance(value, str):
                value = value.strip()
                if not value:
                    raise ValueError(f"{field} must not be blank")
                setattr(self, field, value)
        return self
