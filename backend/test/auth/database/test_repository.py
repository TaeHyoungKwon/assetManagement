# Library
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from uuid import uuid4
from datetime import datetime
from dotenv import load_dotenv
from os import getenv
# Module
from api.v1.auth.database.repository import DBHandler
from api.v1.auth.database.schemas import ProviderEnum, UserRoleEnum
from api.v1.auth.database.models import User
from database.config import PostgresBase  

load_dotenv()
TEST_POSTGRESSQL_URL = getenv('TEST_POSTGRESSQL_URL', None)

engine = create_engine(TEST_POSTGRESSQL_URL)
TestingSessionLocal = sessionmaker(autoflush=False, bind=engine)

# [정보] pytest.fixture는 테스트 환경 생성 및 삭제를 위한 데코레이터입니다.
@pytest.fixture
def db_session():
    PostgresBase.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()

@pytest.fixture
def db_handler():
    return DBHandler()

def test_create_user(db_session, db_handler):
    social_id = "test_social_id"
    provider = ProviderEnum.google  
    role = UserRoleEnum.user  
    nickname = "test_nickname"
    user = db_handler.create_user(db_session, social_id, provider, role, nickname)
    assert user.social_id == social_id
    assert user.provider == provider
    assert user.role == role
    assert user.nickname == nickname

def test_get_user(db_session, db_handler):
    social_id = "test_social_id"
    provider = ProviderEnum.google  
    new_user = User(id=uuid4(), social_id=social_id, provider=provider, created_at=datetime.now())
    db_session.add(new_user)
    db_session.commit()

    retrieved_user = db_handler.get_user(db_session, social_id, provider)
    assert retrieved_user is not None
    assert retrieved_user.social_id == social_id
    assert retrieved_user.provider == provider
