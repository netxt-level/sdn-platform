from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "flow_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_event_id", sa.String(80), nullable=True),
        sa.Column("source_event_fingerprint", sa.String(128), nullable=True),
        sa.Column("analyzer_id", sa.String(30), nullable=False),
        sa.Column("switch_id", sa.String(64), nullable=True),
        sa.Column("target", sa.String(30), nullable=False),
        sa.Column("action", sa.String(30), nullable=False),
        sa.Column("match", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("idle_timeout", sa.Integer(), nullable=True),
        sa.Column("hard_timeout", sa.Integer(), nullable=True),
        sa.Column("rate_limit_pps", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(30), nullable=False, server_default="PENDING"),
        sa.Column("controller_rule_id", sa.String(128), nullable=True),
        sa.Column(
            "controller_response",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        schema="sdn_controller",
    )
    op.create_index(
        "ix_flow_rules_analyzer_id",
        "flow_rules",
        ["analyzer_id"],
        schema="sdn_controller",
    )
    op.create_index(
        "ix_flow_rules_source_event_id",
        "flow_rules",
        ["source_event_id"],
        schema="sdn_controller",
    )
    op.create_index(
        "ix_flow_rules_status",
        "flow_rules",
        ["status"],
        schema="sdn_controller",
    )
    op.create_index(
        "uq_flow_rules_source_event_fingerprint_action",
        "flow_rules",
        ["source_event_fingerprint", "action"],
        unique=True,
        schema="sdn_controller",
    )

    op.execute("""
    CREATE TRIGGER flow_rules_updated_at
    BEFORE UPDATE ON sdn_controller.flow_rules
    FOR EACH ROW
    EXECUTE FUNCTION sdn_controller.update_updated_at_column();
    """)


def downgrade():
    op.execute("""
    DROP TRIGGER IF EXISTS flow_rules_updated_at
    ON sdn_controller.flow_rules;
    """)

    op.drop_index(
        "uq_flow_rules_source_event_fingerprint_action",
        table_name="flow_rules",
        schema="sdn_controller",
    )
    op.drop_index(
        "ix_flow_rules_status",
        table_name="flow_rules",
        schema="sdn_controller",
    )
    op.drop_index(
        "ix_flow_rules_source_event_id",
        table_name="flow_rules",
        schema="sdn_controller",
    )
    op.drop_index(
        "ix_flow_rules_analyzer_id",
        table_name="flow_rules",
        schema="sdn_controller",
    )
    op.drop_table("flow_rules", schema="sdn_controller")
