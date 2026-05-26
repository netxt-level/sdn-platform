from alembic import op


revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.execute("CREATE SCHEMA IF NOT EXISTS sdn_controller")

    op.execute("""
    CREATE OR REPLACE FUNCTION sdn_controller.update_updated_at_column()
    RETURNS TRIGGER AS $$
    BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """)


def downgrade():
    op.execute("""
    DROP FUNCTION IF EXISTS sdn_controller.update_updated_at_column()
    """)

    op.execute("DROP SCHEMA IF EXISTS sdn_controller")
