from alembic import op
import sqlalchemy as sa


revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "analyzer",
        sa.Column("id", sa.String(30), primary_key=True),
        sa.Column("name", sa.String(50), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("capture_active", sa.Boolean, nullable=False),
        sa.Column("backend_connected", sa.Boolean, nullable=False),
        sa.Column("last_packet_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_summary_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        schema="sdn_controller",
    )

    op.execute("""
    CREATE TRIGGER analyzer_updated_at
    BEFORE UPDATE ON sdn_controller.analyzer
    FOR EACH ROW
    EXECUTE FUNCTION sdn_controller.update_updated_at_column();
    """)


def downgrade():
    op.execute("""
    DROP TRIGGER IF EXISTS analyzer_updated_at
    ON sdn_controller.analyzer;
    """)

    op.drop_table("analyzer", schema="sdn_controller")
