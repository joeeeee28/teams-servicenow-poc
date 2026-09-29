from pydantic import BaseModel, Field
from typing import Optional


class CreateIncidentRequest(BaseModel):
    short_description: str = Field(
        ...,
        min_length=1,
        max_length=160,
        description="Short description of the incident",
    )

    description: str = Field(
        ...,
        min_length=1,
        description="Detailed incident description",
    )

    impact: str = Field(
        default="3",
        pattern="^[1-3]$",
        description="Impact: 1=High, 2=Medium, 3=Low",
    )

    urgency: str = Field(
        default="3",
        pattern="^[1-3]$",
        description="Urgency: 1=High, 2=Medium, 3=Low",
    )


class UpdateIncidentRequest(BaseModel):
    short_description: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=160,
    )

    description: Optional[str] = Field(
        default=None,
        min_length=1,
    )

    impact: Optional[str] = Field(
        default=None,
        pattern="^[1-3]$",
    )

    urgency: Optional[str] = Field(
        default=None,
        pattern="^[1-3]$",
    )
