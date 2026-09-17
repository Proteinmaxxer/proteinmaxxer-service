from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    HttpUrl,
    StringConstraints,
    field_validator,
    model_validator,
)

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
Provider = Literal["google", "apple"]


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class ProfileData(InputModel):
    display_name: Name | None = None
    avatar_url: HttpUrl | None = None
    gender: Literal["male", "female", "non_binary", "prefer_not_to_say"] | None = None
    age_range: Literal["18_24", "25_34", "35_44", "45_54", "55_plus"] | None = None
    weight_kg: float | None = Field(default=None, gt=0, le=500)
    height_cm: float | None = Field(default=None, gt=0, le=300)
    workout_frequency: Literal["0_1", "2_3", "4_5", "6_plus"] | None = None
    workout_intensity: Literal["light", "moderate", "hard"] | None = None
    body_goal: Literal["cutting", "body_recomp", "fitness", "bulking"] | None = None
    diet_style: Literal["meats", "vegetarian", "vegan", "dairy_eggs"] | None = None
    allergies: list[
        Literal[
            "dairy",
            "eggs",
            "fish",
            "gluten",
            "peanuts",
            "sesame",
            "shellfish",
            "soy",
            "tree_nuts",
            "diabetes",
            "other",
        ]
    ] = Field(default_factory=list, max_length=11)
    allergy_notes: str | None = Field(default=None, max_length=1000)
    religious_preference: (
        Literal[
            "no_restrictions",
            "halal",
            "jain",
            "hindu_no_beef",
            "kosher",
        ]
        | None
    ) = None
    religious_days: list[
        Literal[
            "lent",
            "ramadan",
            "weekly_fasts",
            "festival_fasts",
            "none",
        ]
    ] = Field(default_factory=list, max_length=5)
    cuisine_preferences: list[
        Literal[
            "american",
            "indian",
            "chinese",
            "mexican",
            "mediterranean",
            "middle_eastern",
            "no_preference",
        ]
    ] = Field(default_factory=list, max_length=7)
    daily_protein_goal_g: float | None = Field(default=None, gt=0, le=1000)
    budget_min_inr: float | None = Field(default=None, ge=0, le=1000000)
    budget_max_inr: float | None = Field(default=None, ge=0, le=1000000)
    skipped: bool = False

    @model_validator(mode="after")
    def validate_budget(self):
        if (
            self.budget_min_inr is not None
            and self.budget_max_inr is not None
            and self.budget_min_inr > self.budget_max_inr
        ):
            raise ValueError("budget_min_inr cannot exceed budget_max_inr")
        return self


class ProfileResponse(ProfileData):
    user_id: str
    created_at: datetime
    updated_at: datetime


class EmailCredentials(InputModel):
    email: EmailStr = Field(max_length=254)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value):
        return str(value).lower()


class SignupRequest(EmailCredentials):
    password: str = Field(min_length=12, max_length=128)
    profile: ProfileData = Field(default_factory=ProfileData)


class SocialLoginRequest(InputModel):
    id_token: str = Field(min_length=1, max_length=16384)
    nonce: str = Field(min_length=32, max_length=256)
    # Apple supplies the name separately on first consent. It is display data only.
    profile: ProfileData = Field(default_factory=ProfileData)


class NonceRequest(InputModel):
    provider: Provider


class NonceResponse(BaseModel):
    nonce: str
    expires_in: int


class RefreshRequest(InputModel):
    refresh_token: str = Field(min_length=32, max_length=256)


class UserResponse(BaseModel):
    id: str
    email: str | None
    email_verified: bool
    providers: list[str]
    created_at: datetime
    profile: ProfileResponse


class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    refresh_expires_in: int
    is_new_user: bool = False
    user: UserResponse
