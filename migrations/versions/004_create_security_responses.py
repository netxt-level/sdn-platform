from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "security_responses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_event_id", sa.String(80), nullable=True),
        sa.Column("source_event_fingerprint", sa.String(128), nullable=True),
        sa.Column("analyzer_id", sa.String(30), nullable=False),
        sa.Column("attack_category", sa.String(50), nullable=True),
        sa.Column("attack_type", sa.String(50), nullable=True),
        sa.Column("severity", sa.String(30), nullable=True),
        sa.Column("recommended_action", sa.String(50), nullable=True),
        sa.Column("response_action", sa.String(50), nullable=False),
        sa.Column("response_level", sa.String(30), nullable=True),
        sa.Column("status", sa.String(30), nullable=False, server_default="PENDING"),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("mitigation", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "response_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("approved_by", sa.String(80), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
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
        "ix_security_responses_analyzer_id",
        "security_responses",
        ["analyzer_id"],
        schema="sdn_controller",
    )
    op.create_index(
        "ix_security_responses_source_event_id",
        "security_responses",
        ["source_event_id"],
        schema="sdn_controller",
    )
    op.create_index(
        "ix_security_responses_status",
        "security_responses",
        ["status"],
        schema="sdn_controller",
    )
    op.create_index(
        "uq_security_responses_event_fingerprint_action",
        "security_responses",
        ["source_event_fingerprint", "response_action"],
        unique=True,
        schema="sdn_controller",
    )

    op.add_column(
        "flow_rules",
        sa.Column("security_response_id", sa.String(36), nullable=True),
        schema="sdn_controller",
    )
    op.create_foreign_key(
        "fk_flow_rules_security_response_id",
        "flow_rules",
        "security_responses",
        ["security_response_id"],
        ["id"],
        source_schema="sdn_controller",
        referent_schema="sdn_controller",
    )
    op.create_index(
        "ix_flow_rules_security_response_id",
        "flow_rules",
        ["security_response_id"],
        schema="sdn_controller",
    )

    op.execute("""
    CREATE TRIGGER security_responses_updated_at
    BEFORE UPDATE ON sdn_controller.security_responses
    FOR EACH ROW
    EXECUTE FUNCTION sdn_controller.update_updated_at_column();
    """)


def downgrade():
    op.execute("""
    DROP TRIGGER IF EXISTS security_responses_updated_at
    ON sdn_controller.security_responses;
    """)

    op.drop_index(
        "ix_flow_rules_security_response_id",
        table_name="flow_rules",
        schema="sdn_controller",
    )
    op.drop_constraint(
        "fk_flow_rules_security_response_id",
        "flow_rules",
        schema="sdn_controller",
        type_="foreignkey",
    )
    op.drop_column(
        "flow_rules",
        "security_response_id",
        schema="sdn_controller",
    )
    op.drop_index(
        "uq_security_responses_event_fingerprint_action",
        table_name="security_responses",
        schema="sdn_controller",
    )
    op.drop_index(
        "ix_security_responses_status",
        table_name="security_responses",
        schema="sdn_controller",
    )
    op.drop_index(
        "ix_security_responses_source_event_id",
        table_name="security_responses",
        schema="sdn_controller",
    )
    op.drop_index(
        "ix_security_responses_analyzer_id",
        table_name="security_responses",
        schema="sdn_controller",
    )
    op.drop_table("security_responses", schema="sdn_controller")
