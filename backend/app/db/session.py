from sqlalchemy.orm import sessionmaker

from app.db.postgres import engine


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)
