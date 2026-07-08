from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from app.core.config import settings


# PostgreSQL 연결에 사용할 SQLAlchemy Engine을 생성
def get_postgres_engine() -> Engine:
    # 커넥션 풀에서 꺼낸 연결이 살아있는지 미리 확인
    return create_engine(
        settings.postgres_dsn,
        pool_pre_ping=True,
    )

# 애플리케이션 전체에서 재사용할 PostgreSQL Engine
engine = get_postgres_engine()
