# Library
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, JSONResponse
from authlib.integrations.starlette_client import OAuthError
from sqlalchemy.orm import Session
from starlette.requests import Request
from aredis import StrictRedis
# Module
from api.v1.auth.service.auth_service import AuthenticationBuilder  
from api.v1.auth.database.schemas import TokenRequest
from api.v1.auth.service.config_service import oauth
from dependencies.dependencies import get_postgres_session, get_redis_pool

authRouter = APIRouter()
authBuilder = AuthenticationBuilder()

@authRouter.post("/google", summary='client 구글 token을 확인후 jwt 토큰을 반환합니다.', description='client 구글 토큰이 넘어오는 지 확인후, 해당 토큰으로 유저확인을 합니다. 신규 유저인 경우 DB에 저장한후, jwt를 반환합니다.')
async def google_login(
            request:TokenRequest, 
            db:Session = Depends(get_postgres_session),
            redis:StrictRedis = Depends(get_redis_pool)
        ):
    access_token = request.access_token
    refresh_token = request.refresh_token

    if not access_token:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"Message":"구글 access token이 넘어오지 않았습니다."})
    
    if not refresh_token:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"Message":"구글 refresh token이 넘어오지 않았습니다."})

    try:
        jwt_token = await authBuilder.google_authenticate(db, redis, access_token, refresh_token)

        return jwt_token
    except HTTPException as e:
        return JSONResponse(status_code=e.status_code, content={"message":e.detail})

@authRouter.get("/google/refresh", summary="client에게 새로운 jwt 토큰을 발급합니다.", description="client가 새로운 jwt 요청시, refresh token으로 인증 후, 새로운 jwt를 발급합니다.")
async def google_jwt_refresh (request: Request, db: Session = Depends(get_postgres_session)):
    old_jwt = await request.json().get('old_jwt')
    
@authRouter.get("/google/logout", summary="구글 로그인 세션 해제", description="JWT를 받아 구글 서비스에서 로그아웃 합니다. 호출 전 구글과의 세션을 끊고, 호출 후 JWT를 프론트엔드에서 버려야 합니다.")
async def google_logout(request:Request, db:Session=Depends(get_postgres_session)):
    pass


@authRouter.get('/naver', summary='네이버 폼으로 redirect합니다.', description="유저가 카카오 로그인 클릭시, 카카오에서 제공하는 폼으로 이동합니다.")
async def redirect_to_naver_login(request: Request):
    redirect_uri = request.url_for("naver_callback")
    return await oauth.naver.authorize_redirect(request, redirect_uri)

@authRouter.get("/naver/callback", summary="네이버 로그인 작업을 합니다.", description="로그인 심사후 홈페이지로 이동합니다.")
async def naver_callback(request: Request, db: Session = Depends(get_postgres_session)):
    try:
        await authBuilder.naver_authenticate(db,request)
        return RedirectResponse(url='/', status_code=303)
    except OAuthError as error:
        return {"error": error.description}

@authRouter.get("/kakao", summary="카카오 폼으로 redirect합니다.", description="유저가 카카오 로그인 클릭시, 카카오에서 제공하는 폼으로 이동합니다.")
async def redirect_to_kakao_login(request: Request):
    redirect_uri = request.url_for("kakao_callback")
    return await oauth.kakao.authorize_redirect(request, redirect_uri)

@authRouter.get("/kakao/callback", summary="카카오 로그인 작업을 합니다.", description="로그인 심사후 홈페이지로 이동합니다.")
async def kakao_callback(request: Request, db: Session = Depends(get_postgres_session)):
    try:
        await authBuilder.kakao_authenticate(db,request)
        return RedirectResponse(url='/', status_code=303)
    except OAuthError as error:
        return {"error": error.description}
