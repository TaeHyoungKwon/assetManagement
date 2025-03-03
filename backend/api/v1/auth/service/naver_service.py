# Library
from fastapi import HTTPException
from starlette.requests import Request
from authlib.integrations.starlette_client import OAuthError
from httpx import AsyncClient
# Module
from api.v1.auth.service.config_service import oauth

async def fetch_naver_user_info(access_token: str):
    url = "https://openapi.naver.com/v1/nid/me"  
    headers = {"Authorization": f"Bearer {access_token}"}
    async with AsyncClient() as client:
        response = await client.get(url, headers=headers)
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="네이버 사용자 정보를 가져오는 데 실패하였습니다.")
        user_info = await response.json()
        return user_info.get('response', {})

async def authenticate_with_naver(request: Request):
    try:
        token = await oauth.naver.authorize_access_token(request)
        user_info = await fetch_naver_user_info(token['access_token'])
        
        if not user_info:
            raise HTTPException(status_code=400, detail="네이버 토큰 내에 유저 고유 ID가 존재하지 않습니다.")
        
        social_id = user_info.get('id')
        return social_id
    except OAuthError as error:
        raise HTTPException(status_code=400, detail=f"OAuth 에러가 발생하였습니다 : {error.error}")
    
