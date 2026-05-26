import os

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

load_dotenv()

# 환경변수 값을 가져오는 공통 함수
def get_env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value


# PostgreSQL 연결에 사용할 SQLAlchemy Engine을 생성
def get_postgres_engine() -> Engine:
    host = get_env("POSTGRES_HOST", "localhost")
    port = get_env("POSTGRES_PORT", "5432")
    user = get_env("POSTGRES_USER")
    password = get_env("POSTGRES_PASSWORD")
    db = get_env("POSTGRES_DB")

    # 커넥션 풀에서 꺼낸 연결이 살아있는지 미리 확인
    return create_engine(
        f"postgresql+psycopg://{user}:{password}@{host}:{port}/{db}",
        pool_pre_ping=True,
    )

# 애플리케이션 전체에서 재사용할 PostgreSQL Engine
engine = get_postgres_engine()

# 분석 서버 상태 정보를 PostgreSQL에 저장하거나 갱신
# 같은 analyzer id가 이미 있으면 INSERT 대신 UPDATE가 수행
def upsert_analyzer_status(payload: dict) -> None:
    
    # analyzer 테이블에 상태 정보를 upsert하는 SQL
    # ON CONFLICT (id)는 id가 중복될 때 기존 행을 갱신
    query = text("""
        INSERT INTO sdn_controller.analyzer (
            id,
            status,
            interface,
            capture_active,
            backend_connected,
            last_packet_at,
            last_summary_sent_at,
            error_message,
            reported_at
        )
        VALUES (
            :id,
            :status,
            :interface,
            :capture_active,
            :backend_connected,
            :last_packet_at,
            :last_summary_sent_at,
            :error_message,
            :reported_at
        )
        ON CONFLICT (id)
        DO UPDATE SET
            status = EXCLUDED.status,
            interface = EXCLUDED.interface,
            capture_active = EXCLUDED.capture_active,
            backend_connected = EXCLUDED.backend_connected,
            last_packet_at = EXCLUDED.last_packet_at,
            last_summary_sent_at = EXCLUDED.last_summary_sent_at,
            error_message = EXCLUDED.error_message,
            reported_at = EXCLUDED.reported_at;
    """)

    # API payload의 필드명을 DB 컬럼/SQL 파라미터 이름에 맞게 매핑
    params = {
        "id": payload["analyzer_id"],
        "status": payload["status"],
        "interface": payload["interface"],
        "capture_active": payload["capture_active"],
        "backend_connected": payload["backend_connected"],
        "last_packet_at": payload.get("last_packet_at"),
        "last_summary_sent_at": payload.get("last_summary_sent_at"),
        "error_message": payload.get("error_message"),
        "reported_at": payload.get("timestamp"),
    }

    # 트랜잭션을 시작하고 SQL을 실행
    # with 블록이 정상 종료되면 commit, 예외가 발생하면 rollback
    with engine.begin() as conn:
        conn.execute(query, params)


def get_analyzer_statuses(analyzer_id: str | None = None) -> list[dict]:
    query = """
        SELECT
            id AS analyzer_id,
            status,
            interface,
            capture_active,
            backend_connected,
            last_packet_at,
            last_summary_sent_at,
            error_message,
            reported_at,
            created_at,
            updated_at
        FROM sdn_controller.analyzer
    """

    params = {}
    if analyzer_id:
        query += " WHERE id = :analyzer_id"
        params["analyzer_id"] = analyzer_id

    query += " ORDER BY reported_at DESC"

    with engine.begin() as conn:
        rows = conn.execute(text(query), params).mappings().all()

    return [dict(row) for row in rows]
