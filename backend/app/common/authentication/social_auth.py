# Library
from abc import ABC, abstractmethod

from sqlalchemy.orm import Session
from starlette.requests import Request
from fastapi import HTTPException
from aredis import StrictRedis
from authlib.integrations.starlette_client import OAuthError
# Module
from app.modules.authentication.schemas import ProviderEnum
from app.modules.authentication.service.google import verify_google_token
from app.modules.authentication.service.kakao import authenticate_with_kakao
from app.modules.authentication.service.naver import authenticate_with_naver
from app.common.authentication.jwt import generate_jwt
from app.modules.authentication.repository import DBHandler

# [수정] Strategy Pattern을 활용해, social auth따라 인증합니다.

class AuthenticationBuilder(DBHandler):
    async def google_authenticate(self, db: Session, redis:StrictRedis , access_token:str, refresh_token:str):
        try:
            id_info = await verify_google_token(access_token)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except HTTPException as e:
            raise e
        
        user_info = id_info.get('userinfo')
        social_id = user_info.get('sub')

        user = self.get_or_create_user(db, social_id, ProviderEnum.google)
        jwt_token = generate_jwt(user.id, refresh_token)
        
        await redis.set(f"google_{user.id}", refresh_token, ex=3600)

        return jwt_token
    
    
    async def naver_authenticate(self, db:Session, request: Request):
        try:
            social_id = await authenticate_with_naver(request)
        except HTTPException as e:
            raise e
        except OAuthError as error:
            raise HTTPException(status_code=400, detail=f"OAuth 에러가 발생하였습니다 : {error.error}")

        social_id = str(social_id)
        
        user = self.get_user(db, social_id, ProviderEnum.naver)
        if user is None:
            user = self.create_user(db, social_id, ProviderEnum.naver)
        return user
    
    async def kakao_authenticate(self, db:Session, request: Request):
        try:
            social_id = await authenticate_with_kakao(request)
        except HTTPException as e:
            raise e
        except OAuthError as error:
            raise HTTPException(status_code=400, detail=f"OAuth 에러가 발생하였습니다 : {error.error}")

        social_id = str(social_id)
        user = self.get_user(db, social_id, ProviderEnum.kakao)
        if user is None:
            user = self.create_user(db, social_id, ProviderEnum.kakao)
        return user




class SocialLoginAuthentication(ABC):
    def __init__(self, db: Session, request: Request = None, redis: StrictRedis = None, access_token:str = None, refresh_token:str = None):
        self.db = db
        self.request = request
        self.redis = redis
        self.access_token = access_token
        self.refresh_token = refresh_token

    @abstractmethod
    async def authenticate(self):
        raise NotImplementedError("authenticate method is not implemented.")


class Google(SocialLoginAuthentication):
    def __init__(self, db_handler):
        super().__init__()
        self.db_handler = db_handler
    async def authenticate(self):
        try:
            id_info = await verify_google_token(self.access_token)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except HTTPException as e:
            raise e

        user_info = id_info.get('userinfo')
        social_id = user_info.get('sub')

        user = self.db_handler.get_or_create_user(self.db, social_id, ProviderEnum.google)
        jwt_token = generate_jwt(user.id, self.refresh_token)

        await self.redis.set(f"google_{user.id}", self.refresh_token, ex=3600)

        return jwt_token


class Naver(SocialLoginAuthentication):
    def __init__(self, db_handler):
        super().__init__()
        self.db_handler = db_handler
    async def authenticate(self):
        try:
            social_id = await authenticate_with_naver(self.request)
        except HTTPException as e:
            raise e
        except OAuthError as error:
            raise HTTPException(status_code=400, detail=f"OAuth 에러가 발생하였습니다 : {error.error}")

        social_id = str(social_id)

        user = self.db_handler.get_user(self.db, social_id, ProviderEnum.naver)
        if user is None:
            user = self.db_handler.create_user(self.db, social_id, ProviderEnum.naver)
        return user


class KaKao(SocialLoginAuthentication):
    def __init__(self, db_handler):
        super().__init__()
        self.db_handler = db_handler
    async def authenticate(self):
        try:
            social_id = await authenticate_with_kakao(self.request)
        except HTTPException as e:
            raise e
        except OAuthError as error:
            raise HTTPException(status_code=400, detail=f"OAuth 에러가 발생하였습니다 : {error.error}")

        social_id = str(social_id)
        user = self.db_handler.get_user(self.db, social_id, ProviderEnum.kakao)
        if user is None:
            user = self.db_handler.create_user(self.db, social_id, ProviderEnum.kakao)
        return user
