from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

from security.passwords import hash_password

from schemas.accounts import (
    UserRegistrationRequestSchema, UserRegistrationResponseSchema, MessageResponseSchema,
    UserActivationRequestSchema, PasswordResetResponseSchema, PasswordResetRequestSchema,
    PasswordResetCompleteResponseSchema, PasswordResetCompleteRequestSchema, UserLoginRequestSchema,
    UserLoginResponseSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
)

router = APIRouter()


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    hashed_password = hash_password(user.password)

    if user.group_id is None:
        result = await db.execute(
            select(UserGroupModel.id).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        user.group_id = result.scalar_one()

    activation_token = ActivationTokenModel()
    db_user = UserModel(
        email=user.email,
        _hashed_password=hashed_password,
        group_id=user.group_id,
        activation_token=activation_token,
    )

    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def register_user(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {db_user.email} already exists.")
    try:
        db_user = await create_user(db, user)
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")
    return db_user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)

    get_token = await db.execute(select(ActivationTokenModel).where(ActivationTokenModel.user_id == db_user.id))
    token = get_token.scalar_one_or_none()
    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    elif not token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    elif token.expires_at < datetime.now():
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    else:
        if user.token == token.token:
            db_user.is_active = True
            await db.delete(token)
            await db.commit()
            await db.refresh(db_user)
            return MessageResponseSchema()


@router.post("/password-reset/request/", response_model=PasswordResetResponseSchema)
async def password_reset_request(user: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)

    if db_user and db_user.is_active:
        reset_token = PasswordResetTokenModel(user=db_user)
        db.add(reset_token)
        await db.commit()
        await db.refresh(reset_token)

    return PasswordResetResponseSchema()


@router.post("/reset-password/complete/", response_model=PasswordResetCompleteResponseSchema)
async def password_reset_complete(user: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)

    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    result = await db.execute(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id))
    token = result.scalar_one_or_none()

    if token.expires_at < datetime.now() or token.token != user.token:
        await db.delete(token)
        await db.commit()

        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        db_user.password = user.password
        await db.delete(token)
        await db.commit()
        await db.refresh(db_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    return PasswordResetResponseSchema()


@router.post("/login/", response_model=UserLoginResponseSchema)
async def login(user: UserLoginRequestSchema, db: AsyncSession = Depends(get_db),
                jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
                settings: BaseAppSettings = Depends(get_settings)
                ):
    db_user = await get_user_by_email(db, user.email)

    if not db_user or not db_user.verify_password(user.password):
        raise HTTPException(status_code=401, detail="Invalid email or token.")

    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    payload = {"user_id": db_user.id, "email": db_user.email}
    try:
        access_token = jwt_manager.create_access_token(payload, expires_delta=timedelta(minutes=60))
        refresh_token = jwt_manager.create_refresh_token(
            payload, expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS))

        save_refresh_token = RefreshTokenModel.create(db_user.id, settings.LOGIN_TIME_DAYS, token=refresh_token)

        db.add(save_refresh_token)
        await db.commit()
        await db.refresh(save_refresh_token)

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            type="bearer"
        )
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_token(
        user: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    try:
        payload = jwt_manager.decode_refresh_token(user.refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    db_user = await get_user_by_email(db, payload["email"])

    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=404, detail="User not found.")

    token_obj = next((t for t in db_user.refresh_tokens if t.token == user.refresh_token), None)
    if token_obj.expires_at < datetime.now():
        raise HTTPException(status_code=400, detail="Token has expired.")

    new_access_token = jwt_manager.create_access_token({"user_id": db_user.id, "email": db_user.email})

    new_refresh_token = jwt_manager.create_refresh_token({"user_id": db_user.id, "email": db_user.email},
                                                         expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS))
    refresh_token_obj = RefreshTokenModel.create(db_user.id, settings.LOGIN_TIME_DAYS, token=new_refresh_token)
    db.add(refresh_token_obj)
    await db.commit()
    await db.refresh(refresh_token_obj)

    return TokenRefreshResponseSchema(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        type="bearer"
    )
