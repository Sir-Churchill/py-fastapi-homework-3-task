from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str
    group_id: int = 1

    @field_validator("password")
    def validate_password(cls, value):
        accounts_validators.validate_password_strength(value)
        return value

    @field_validator("email")
    def validate_email_user(cls, value):
        accounts_validators.validate_email(value)
        return value


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str = "User account activated successfully."


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetResponseSchema(BaseModel):
    message: str = "If you are registered, you will receive an email with instructions."


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    def validate_password(cls, value):
        accounts_validators.validate_password_strength(value)
        return value


class PasswordResetCompleteResponseSchema(BaseModel):
    message: str = "Password reset successfully."


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
