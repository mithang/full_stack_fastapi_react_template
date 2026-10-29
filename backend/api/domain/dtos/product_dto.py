from pydantic import BaseModel, Field


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
