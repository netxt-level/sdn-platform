from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy import text

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


def is_postgres_ready() -> bool:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            required_tables = (
                "sdn_controller.analyzer",
                "sdn_controller.flow_rules",
                "sdn_controller.security_responses",
            )
            for table_name in required_tables:
                result = connection.execute(
                    text("SELECT to_regclass(:table_name)"),
                    {"table_name": table_name},
                ).scalar()
                if result is None:
                    return False
        return True
    except Exception:
        return False
